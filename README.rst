#######
Sleeter
#######

sleeter is a simple tool to help quickly and easily deploy a static website to AWS S3 and publish it to the Cloudfront CDN.
It is written in Python 3.7 and uses the boto3 library


Requirements
============

* An AWS account
* An AWS user with both 'programatic' and 'administrator' access
* Your AWS user's access key id and secret access key in your ~/.aws/credentials file
* A Route53 hosted zone for the domain you wish to use
* Python 3.7
* 

Installation
============

Usage
=====


.. code-block:: bash
    
    usage: sleeter [-h] --site-name SITE_NAME --site-files SITE_FILES
                   [--region REGION] [--index-suffix INDEX_SUFFIX]
                   [--error-document ERROR_DOCUMENT]
                   [--aws-profile AWS_PROFILE]

Quickstart
^^^^^^^^^^

Assuming your AWS credentials are set as default and the home page of your site is ``index.html``, you can deploy the
site found at ``/path/to/mysite`` to the url ``mysite.example.com`` with:

.. code-block:: bash
    
    sleeter --site-name mysite.example.com --site-files /path/to/mysite



