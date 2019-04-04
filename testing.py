#!/usr/bin/env python3

"""
Tests to make sure that the fh_disable_network_modification policy
indeed prevents users from invoking network operations.
"""

import boto3
import botocore


def main():
    "do the work"

    # start w/credentials in environment tied to fred hutch account
    sts = boto3.client("sts")

    # assume role in cortex production account
    print("Assuming role in cortex production account...")
    resp = sts.assume_role(
        RoleArn="arn:aws:iam::329997391649:role/admin-with-limited-network",
        RoleSessionName="polecat",
    )

    # get ec2 client in cortex production account
    ec2 = boto3.client(
        "ec2",
        aws_access_key_id=resp["Credentials"]["AccessKeyId"],
        aws_secret_access_key=resp["Credentials"]["SecretAccessKey"],
        aws_session_token=resp["Credentials"]["SessionToken"],
        region_name="us-west-2",
    )

    # try to create a vpc
    print("Trying to create a VPC...")
    try:
        ec2.create_vpc(CidrBlock="", DryRun=True)
        print("FAIL: able to create VPC")
    except botocore.exceptions.ClientError as exc:
        if "UnauthorizedOperation" in str(exc):
            print("SUCCESS: unable to create VPC")
        else:
            print("FAIL: Got a different client error")
    except Exception as exc:  # pylint: disable=broad-except
        print("FAIL: Got a different error: {}".format(str(exc)))


if __name__ == "__main__":
    main()
