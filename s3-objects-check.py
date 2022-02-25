import argparse
import asyncio
import csv
import logging
import time

import aiobotocore
import botocore
import coloredlogs
from aiobotocore.config import AioConfig
from botocore import UNSIGNED

LOGGER = logging.getLogger('object-check')


async def write_result(bucket_name, object_key, content_type, object_url, access_type, writer):
    async with asyncio.Lock():  # lock for gracefully write to shared file object
        writer.writerow([bucket_name, object_key, content_type, object_url, access_type])


async def test_get_object(bucket_name, object_key, client):
    try:
        obj = await client.get_object(Bucket=bucket_name, Key=object_key, Range='bytes=0-9')
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            pass  # this is expected
        else:
            LOGGER.error(f'Client error getting object {object_key} from {bucket_name}: {e}')
    except Exception as e:
        LOGGER.error(f'Unknown error getting object {object_key} from {bucket_name}: {e}')
    else:
        return obj

    return False


async def test_object(bucket_name, bucket_region,
                      object_key,
                      bb_client, anonymous_client,
                      csv_writer):
    object_url = f'https://{bucket_name}.s3.{bucket_region}.amazonaws.com/{object_key}'

    all_users = await test_get_object(bucket_name, object_key, anonymous_client)

    if all_users:
        LOGGER.warning(f'Found {object_url} allowing "AllUsers"')
        await write_result(bucket_name, object_key, all_users.get('ContentType'),
                           object_url, 'AllUsers', csv_writer)
    else:
        authenticated_users = await test_get_object(bucket_name, object_key, bb_client)
        if authenticated_users:
            LOGGER.warning(f'Found {object_url} allowing "AuthenticatedUsers"')
            await write_result(bucket_name, object_key, authenticated_users.get('ContentType'),
                               object_url, 'AuthenticatedUsers', csv_writer)


async def test_bucket(bucket_name, bucket_region,
                      wb_client, bb_client, anonymous_client,
                      csv_writer):
    LOGGER.debug(f'Launching tests for bucket {bucket_name}')
    paginator = wb_client.get_paginator("list_objects")
    page_iterator = paginator.paginate(Bucket=bucket_name)
    object_tasks = []
    for page in page_iterator:
        try:
            p = await page
        except Exception as e:
            LOGGER.error(f'Unable to list objects from bucket {bucket_name}: {e}')
        else:
            if "Contents" in p:
                for obj in p["Contents"]:
                    if obj.get('Size') > 0:
                        object_tasks.append(test_object(bucket_name, bucket_region,
                                                        obj.get('Key'),
                                                        bb_client, anonymous_client,
                                                        csv_writer))
    await asyncio.gather(*object_tasks)


async def run(args):
    LOGGER.info('Starting')

    # authenticated sessions
    wb_session = aiobotocore.AioSession(profile=args.whitebox_profile)
    bb_session = aiobotocore.AioSession(profile=args.blackbox_profile)
    # unauthenticated session
    config = AioConfig(signature_version=UNSIGNED)
    session = aiobotocore.get_session()

    async with session.create_client('s3', region_name='us-east-1', config=config) as anonymous_client:
        async with wb_session.create_client('s3', region_name='us-east-1') as wb_client:
            async with bb_session.create_client('s3', region_name='us-east-1') as bb_client:
                with open(f's3-whitebox_results_{args.whitebox_profile}_{time.strftime("%Y-%m-%d-%H%M%S")}.csv',
                          'a') as csv_out:
                    csv_writer = csv.writer(csv_out, delimiter=',')
                    csv_writer.writerow(['bucket', 'object', 'content-type', 'url', 'access'])

                    buckets = await wb_client.list_buckets()
                    bucket_tasks = []
                    for bucket in buckets.get('Buckets'):
                        try:
                            bucket_location = await wb_client.get_bucket_location(Bucket=bucket.get('Name'))
                            bucket_region = bucket_location.get('LocationConstraint', 'us-east-1')
                            if not bucket_region:
                                bucket_region = 'us-east-1'
                        except Exception as e:
                            bucket_region = 'us-east-1'
                        finally:
                            if args.list == None or bucket.get('Name') in args.list:
                                LOGGER.info("Adding..."+bucket.get('Name'))
                                bucket_tasks.append(test_bucket(bucket.get('Name'), bucket_region,
                                                                wb_client, bb_client, anonymous_client,
                                                                csv_writer))
                    await asyncio.gather(*bucket_tasks)

    LOGGER.info('Done')


if __name__ == "__main__":

    # Arguments parser
    parser = argparse.ArgumentParser(
        description='Whitebox evaluation of effective S3 object permissions, to identify publicly accessible files.')
    parser.add_argument('-p', '--profile',
                        dest='whitebox_profile',
                        help='The profile with access to the desired AWS account and buckets',
                        required=True)
    parser.add_argument('-e', '--profile-external',
                        dest='blackbox_profile',
                        help='An "external" profile to test for \'AuthenticatedUsers\' permissions. '
                             'This principal should not have permissions to read bucket objects.',
                        required=True)
    parser.add_argument('-d', '--debug',
                        dest='debug',
                        action='store_true',
                        help='Verbose output. Will also create a log file',
                        required=False,
                        default=False)
    parser.add_argument('-l', '--bucket-list',
                        dest='list',
                        nargs="+",
                        help='Specify a list of buckets for the scan',
                        required=False,
                        default=None)

    args = parser.parse_args()

    if args.debug:
        fh = logging.FileHandler(f's3-whitebox_debug_log-{time.strftime("%Y-%m-%d-%H%M%S")}.log')
        fh.setLevel(logging.DEBUG)
        LOGGER.addHandler(fh)
        coloredlogs.install(level='DEBUG', logger=LOGGER)
    else:
        coloredlogs.install(level='INFO', logger=LOGGER)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(args))
