#!/usr/bin/env python3

"""
Tests to make sure that the fh_disable_network_modification policy
indeed prevents users from invoking network operations.
"""
import unittest

import boto3
import botocore


class TestRoleCannotDoNetworkStuff(unittest.TestCase):
    "test cases"

    def test_cannot_create_vpc(self):
        "do the work"

        # start w/credentials in environment tied to fred hutch account
        sts = boto3.client("sts")

        # assume role in cortex production account
        # This role has both full administrative access AND the
        # fh_disable_network_modification policy attached.
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
        try:
            ec2.create_vpc(CidrBlock="", DryRun=True)
            self.fail("able to create VPC")
        except botocore.exceptions.ClientError as exc:
            self.assertTrue("UnauthorizedOperation" in str(exc))
        except Exception as exc:  # pylint: disable=broad-except
            self.fail("Got an unexpected error: {}".format(str(exc)))

    def test_assume_role_in_cortex_security_account(self):
        """
        Double role assumption.
        """
        # start w/credentials in environment tied to fred hutch account
        sts = boto3.client("sts")

        # assume role in cortex production account
        # This role has both full administrative access AND the
        # fh_disable_network_modification policy attached.
        resp = sts.assume_role(
            RoleArn="arn:aws:iam::329997391649:role/admin-with-limited-network",
            RoleSessionName="polecat",
        )

        # get sts client in cortex-production account so
        # we can assume a role again
        sts2 = boto3.client(
            "sts",
            aws_access_key_id=resp["Credentials"]["AccessKeyId"],
            aws_secret_access_key=resp["Credentials"]["SecretAccessKey"],
            aws_session_token=resp["Credentials"]["SessionToken"],
            region_name="us-west-2",
        )

        # assume role in cortex security account
        # This role has both full administrative access AND the
        # fh_disable_network_modification policy attached.
        resp2 = sts2.assume_role(
            RoleArn="arn:aws:iam::775606665510:role/transit-gw-testing",
            RoleSessionName="endive",
        )

        # get ec2 client in cortex security account
        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=resp2["Credentials"]["AccessKeyId"],
            aws_secret_access_key=resp2["Credentials"]["SecretAccessKey"],
            aws_session_token=resp2["Credentials"]["SessionToken"],
            region_name="us-west-2",
        )

        # try to create a vpc
        try:
            ec2.create_vpc(CidrBlock="", DryRun=True)
            self.fail("able to create VPC")
        except botocore.exceptions.ClientError as exc:
            self.assertTrue("UnauthorizedOperation" in str(exc))
        except Exception as exc:  # pylint: disable=broad-except
            self.fail("Got an unexpected error: {}".format(str(exc)))


if __name__ == "__main__":
    unittest.main(warnings="ignore")
