# S3 Objects Check

## Description

Whitebox evaluation of effective S3 object permissions, in order to identify publicly accessible objects.

Allows identifying publicly accessible objects, as well as objects accessible for `AuthenticatedUsers` (by using a secondary profile). 
A number of tools exist which check permissions on buckets, but due to the complexity of IAM resource policies and ACL combinations, the effective permissions on specific objects is often hard to assess.
The tool runs fast as it uses [asyncio](https://docs.python.org/3/library/asyncio.html) and [aiobotocore](https://github.com/aio-libs/aiobotocore).

## Setup

### Permissions

The tool leverages two [named profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html):
- `WHITEBOX_PROFILE` - this profile should have read access to the S3 service. It will be used to list buckets and objects, which the tool will then attempt to access via **unauthenticated** requests. It's not used to access the objects, only to list them.
- `BLACKBOX_PROFILE` - in addition to the unauthenticated requests, the tool will use this profile to identify objects accessible to the "[Authenticated Users group](https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#specifying-grantee-predefined-groups)" (`AuthenticatedUsers`). This profile should **not** have access to the S3 buckets/objects, otherwise it will raise false positives.

### Dependencies

Setup a virtual environment and install dependencies:

```shell script
$ virtualenv -p python3 venv
$ source venv/bin/activate
$ pip -r requirements.txt
```

## Usage

Options:

```shell script
$ python s3-objects-check.py -h                                                                                        

usage: s3-objects-check.py [-h] -p WHITEBOX_PROFILE -e BLACKBOX_PROFILE [-d]

Whitebox evaluation of effective S3 object permissions, to identify publicly
accessible files.

optional arguments:
  -h, --help            show this help message and exit
  -p WHITEBOX_PROFILE, --profile WHITEBOX_PROFILE
                        The profile with access to the desired AWS account and
                        buckets
  -e BLACKBOX_PROFILE, --profile-external BLACKBOX_PROFILE
                        An "external" profile to test for 'AuthenticatedUsers'
                        permissions. This principal should not have
                        permissions to read bucket objects.
  -d, --debug           Verbose output. Will also create a log file
  -l BUCKET_LIST [BUCKET_LIST ...], --bucket-list BUCKET_LIST [BUCKET_LIST ...]
                        Specify a list of targeted buckets
```

Run the tool:

```shell script

$ python s3-objects-check.py -p whitebox-profile -e blackbox-profile -l <bucket-1>  <bucket-2>                                                                                    

2020-11-24 11:19:56 host object-check[371] INFO Starting
2020-11-24 11:20:08 host object-check[371] WARNING Found https://<bucket-1>.s3.us-east-1.amazonaws.com/<object> allowing "AllUsers"
2020-11-24 11:20:09 host object-check[371] WARNING Found https://<bucket-2>.s3.eu-west-2.amazonaws.com/<object> allowing "AuthenticatedUsers"
2020-11-24 11:21:34 host object-check[371] INFO Done

```
