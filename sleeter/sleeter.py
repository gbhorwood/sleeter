# -*- coding: utf-8 -*-

__version__ = "0.1.0"

import sys
import time
import boto3

# @todo the weird dns issue. fix it.
# @todo figure out validation in argparse
# @todo fill out help
# @todo deal with hosted zones list over 100 in validate_hosted_zone
# @todo pass args instead of global


# boto3 clients
boto3_client_s3 = None
boto3_client_route53 = None
boto3_client_acm = None
boto3_client_cloudfront = None

# aws credentials read from ~/.aws/credentials
aws_access_key_id = None
aws_secret_access_key = None

# holds command line arguments
args = None

# url of the web-hosted s3 site
s3_site_endpoint = None
s3_bucket_name = None
# the hosted zone
route53_hosted_zone_name = None
route53_hosted_zone_id = None
# the ARN of the ACM certificate for the site
acm_arn = None

# ANSI display constants
ESC = "\033"
BOLD_ANSI = ESC+"[1m"
GREEN_ANSI = ESC+"[32m"
YELLOW_ANSI = ESC+"[33m"
RED_ANSI = ESC+"[31m"
CLOSE_ANSI = ESC+"[0m"
OK = "["+GREEN_ANSI+"OK"+CLOSE_ANSI+"]"
NOTICE = "["+YELLOW_ANSI+"NOTICE"+CLOSE_ANSI+"]"
ERROR = "["+RED_ANSI+"ERROR"+CLOSE_ANSI+"]"


def make_bucket():
    """
    Creates a public bucket for website hosting
    """

    import os

    global s3_site_endpoint
    global s3_bucket_name

    header("Making bucket")

    # create the s3 bucket
    try:
        response = boto3_client_s3.create_bucket(
            ACL="public-read",
            Bucket=args.site_name,
        )
        testResponse(response, "create_bucket")
    except Exception as e:
        error(e, True)

    # set the policy
    policy = """{
        "Version": "2008-10-17",
        "Id": "PolicyForPublicWebsiteContent",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*"
                },
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::%s/*"
            }
        ]
    }""" % (args.site_name)

    try:
        boto3_client_s3.put_bucket_policy(
            Bucket=args.site_name,
            Policy=policy
        )
        testResponse(response, "put_bucket_policy")
    except Exception as e:
        error(e, True)

    # make bucket a website
    try:
        response = boto3_client_s3.put_bucket_website(
            Bucket=args.site_name,
            WebsiteConfiguration={
                'ErrorDocument': {
                    'Key': args.error_document
                },
                'IndexDocument': {
                    'Suffix': args.index_suffix
                }
            }
        )
        testResponse(response, "put_bucket_website")
    except Exception as e:
        error(e, True)

    # get bucket website to confirm it's there
    try:
        response = boto3_client_s3.get_bucket_website(Bucket=args.site_name)
        testResponse(response, "get_bucket_website")
    except Exception as e:
        error(e, True)

    # sync site-files to bucket at site-name
    # alternate model idea here: https://github.com/boto/boto3/issues/358
    header("Syncing files to bucket")
    aws_s3_sync = "aws s3 sync "+args.site_files+" s3://"+args.site_name+" --profile "+args.aws_profile
    os.system(aws_s3_sync)
    ok("Files synced to s3://"+args.site_name)

    # build the endpoint for the s3 site
    s3_site_endpoint = args.site_name+".s3-website-"+args.region+".amazonaws.com"
    ok("Static website at: http://"+s3_site_endpoint)

    # build bucket name
    s3_bucket_name = args.site_name+".s3.amazonaws.com"


def make_cloudfront():

    global s3_bucket_name
    global s3_site_endpoint

    header("Making cloudfront distribution")

    # caller_reference is a unique identifier used to prevent making the same
    # call twice
    caller_reference = route53_hosted_zone_name + str(time.time())


                        #'S3OriginConfig': {
                        #    'OriginAccessIdentity': ''
                        #}

    response = boto3_client_cloudfront.create_distribution(
        DistributionConfig={
            'CallerReference': caller_reference,
            'Aliases': {
                'Quantity': 1,
                'Items': [args.site_name],
            },
            'DefaultRootObject': args.index_suffix,
            'Origins': {
                'Quantity': 1,
                'Items': [
                    {
                        'Id': '1',
                        'DomainName': s3_site_endpoint,
                        'CustomOriginConfig': {
                            'HTTPPort': 80,
                            'HTTPSPort': 443,
                            'OriginProtocolPolicy': 'match-viewer',
                            'OriginSslProtocols': {
                                'Quantity': 1,
                                'Items': [
                                    'TLSv1.1'
                                ]
                            }
                        }
                    }
                ]
            },
            'DefaultCacheBehavior': {
                'TargetOriginId': '1',
                'ForwardedValues': {
                    'QueryString': True,
                    'Cookies': {
                        'Forward': 'none'
                    }
                },
                'TrustedSigners': {
                    'Enabled': False,
                    'Quantity': 0
                },
                'ViewerProtocolPolicy': 'allow-all',
                'MinTTL': 0
            },
            'ViewerCertificate': {
                'CloudFrontDefaultCertificate': False,
                'ACMCertificateArn': acm_arn,
                'SSLSupportMethod': 'sni-only',
                'MinimumProtocolVersion': 'TLSv1.1_2016'
            },
            'Comment': 'Distribution for '+args.site_name,
            'Enabled': True
        }
    )

    testResponse(response, "create_distribution")


def make_acm():
    global acm_arn

    header("Making ACM")

    # requrest an acm certificate and get its arn
    # acm requires dns verification
    try:
        response = boto3_client_acm.request_certificate(
            DomainName=args.site_name,
            ValidationMethod="DNS"
        )

        testResponse(response, "put_bucket_website")
        acm_arn = response.get('CertificateArn')
    except Exception as e:
        error(e, True)

    # wait for the acm request to be ready before trying to select it
    try:
        notice("Waiting for ACM request to be ready")
        for i in range(300):
            time.sleep(1)
            response = boto3_client_acm.describe_certificate(
                CertificateArn=acm_arn
            )
            if 'ResourceRecord' in response.get('Certificate').get('DomainValidationOptions')[0]:
                print("")
                break
            else:
                print('.')
                #print('.', end='', flush=True)

    except Exception as e:
        error(e, True)

    # test for timeout on waiting for ACM request
    if i == 299:
        error("Timeout waiting for ACM request to complete")
    else:
        ok("ACM request ready (took {} seconds)".format(i+1))

    # get info on the acm used to create the route53 dns record needed
    # to verify the acm
    acm_route53_name = response.get('Certificate').get('DomainValidationOptions')[0].get('ResourceRecord').get('Name')
    acm_route53_value = response.get('Certificate').get('DomainValidationOptions')[0].get('ResourceRecord').get('Value')
    acm_route53_type = response.get('Certificate').get('DomainValidationOptions')[0].get('ResourceRecord').get('Type')

    # DNS is used to verify our ACM so a CNAME record for this domain needs to be created in route53
    try:
        response = boto3_client_route53.change_resource_record_sets(
            HostedZoneId=route53_hosted_zone_id,
            ChangeBatch={
                'Comment': 'For ACM',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': acm_route53_name,
                            'Type': acm_route53_type,
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': acm_route53_value
                                }
                            ]
                        }

                    }
                ]
            }
        )
    except Exception as e:
        error(e, True)


def make_boto3_clients():
    """
    Creates all the boto3 clients needed.

    Sets, globally, the following:
        - boto_client_s3
        - boto_client_route53
        - boto_client_acm
    """

    # s3
    global boto3_client_s3
    try:
        boto3_client_s3 = boto3.client(
            's3',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=args.region,
        )
    except Exception as e:
        error(e, True)

    # route53
    global boto3_client_route53
    try:
        boto3_client_route53 = boto3.client(
            'route53',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=args.region,
        )
    except Exception as e:
        error(e, True)

    # acm
    global boto3_client_acm
    try:
        boto3_client_acm = boto3.client(
            'acm',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=args.region,
        )
    except Exception as e:
        error(e, True)

    # cloudfront
    global boto3_client_cloudfront
    try:
        boto3_client_cloudfront = boto3.client(
            'cloudfront',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=args.region,
        )
    except Exception as e:
        error(e, True)


def get_aws_credentials():
    import configparser
    import os

    global aws_access_key_id
    global aws_secret_access_key

    header("Getting AWS credentials")

    path = os.environ['HOME']+'/.aws/credentials'
    config = configparser.ConfigParser()
    config.read(path)

    if args.aws_profile in config.sections():
        aws_access_key_id = config[args.aws_profile]['aws_access_key_id']
        aws_secret_access_key = config[args.aws_profile]['aws_secret_access_key']
    else:
        error("Cannot find profile '{}' in {}".format(args.aws_profile, path), True)

    if aws_access_key_id is None or aws_secret_access_key is None:
        error("AWS config values not set in '{}' in {}".format(args.aws_profile, path), True)

    ok("AWS credentials found")


def validate_args():
    # validate site-files is dir and is readable
    # validate that `aws` is in path and executable
    return True


def get_args():
    import argparse

    global args

    help_description = """
    Desc
    """

    help_epilog = """
    Epilog
    """
    parser = argparse.ArgumentParser(description=help_description,
                                     epilog=help_epilog)

    # --site-name
    parser.add_argument('--site-name',
                        required=True,
                        dest="site_name",
                        help="The full url of the site, ie 'example.ca'")

    # --site-files
    parser.add_argument('--site-files',
                        required=True,
                        dest="site_files",
                        help="The path to the directory containing the site files, ie /path/to/www")

    # --region
    parser.add_argument('--region',
                        required=False,
                        dest="region",
                        default="us-east-1",
                        help="(Optional)The AWS deploy region. Default 'us-east-1'")

    # --index-suffix
    parser.add_argument('--index-suffix',
                        required=False,
                        dest="index_suffix",
                        default="index.html",
                        help="(Optional) The index page name. Default 'index.html'")

    # --error-document
    parser.add_argument('--error-document',
                        required=False,
                        dest="error_document",
                        default="index.html",
                        help="(Optional) The error page name. Default 'index.html'")

    # --aws-profile
    parser.add_argument('--aws-profile',
                        required=False,
                        dest="aws_profile",
                        default="default",
                        help="(Optional) The named AWS credentials profile. Default profile if not set.")

    args = parser.parse_args()


def validate_hosted_zone():
    """
    Validates that the domain of the site_name passed to the script 
    has a route53 hosted zone for this AWS user
    """

    global route53_hosted_zone_name
    global route53_hosted_zone_id

    # get the domain of the site_name to confirm it's a valid route 53 hosted zone
    route53_hosted_zone_name = args.site_name.split(".")[-2]+"."+args.site_name.split(".")[-1].lower()

    header("Validating hosted zone")

    # get list of hosted zones
    try:
        response = boto3_client_route53.list_hosted_zones()
        testResponse(response, "list_hosted_zones")
    except Exception as e:
        error(e, True)

    hosted_zone_record = None
    hosted_zone_record = list(filter(lambda i: i['Name'][:-1] == route53_hosted_zone_name, response['HostedZones']))

    if hosted_zone_record is None:
        error("Domain "+route53_hosted_zone_name+" is not a Route 53 hosted zone", True)

    route53_hosted_zone_name = hosted_zone_record[0].get('Name')
    route53_hosted_zone_id = hosted_zone_record[0].get('Id')

    ok("Hosted zone "+route53_hosted_zone_name+" valid")


def ok(message):
    """
    Prints message with a green OK prepended
    """

    print(OK, message)


def notice(message):
    """
    Prints message with a yellow NOTICE prepended
    """
    print(NOTICE, message)


def error(message, fatal=False):
    """
    Prints message with a red ERROR prepended. Quits script if fatal=true.
    """
    print(ERROR, message)
    if fatal:
        sys.exit()


def header(message):
    """
    Prints message as bold for header
    """
    print(BOLD_ANSI, message, CLOSE_ANSI)


def testResponse(response, name):
    """
    Prints the HTTP status response from AWS
    """
    http_status = response.get('ResponseMetadata').get('HTTPStatusCode')
    print(OK, name, http_status)


def main():
    """
    Start point for script
    """

    # Parse the args from the command in the global args variable
    get_args()

    # Validates that the args are good
    validate_args()

    # Retreive AWS credentials from ~/.aws/credentials and set
    get_aws_credentials()

    # Make boto3 clients form s3, route53, acm and cloudfront
    make_boto3_clients()

    # Validate that the user has a hosted zone in route54 for the domain requested
    validate_hosted_zone()

    # Make the s3 bucket, set for static hosting, upload the site files
    make_bucket()

    # Create the acm certificate necessary for cloudfront
    #make_acm()

    #make_cloudfront()

