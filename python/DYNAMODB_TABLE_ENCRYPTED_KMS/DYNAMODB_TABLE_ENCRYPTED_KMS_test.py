import unittest
from mock import patch, MagicMock
from rdklib import Evaluation, ComplianceType
import rdklibtest

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::::Account'
MODULE = __import__('DYNAMODB_TABLE_ENCRYPTED_KMS')
RULE = MODULE.DYNAMODB_TABLE_ENCRYPTED_KMS()
CLIENT_FACTORY = MagicMock()
DB_CLIENT_MOCK = MagicMock()

MOCK_NON_COMP = {"Table": {"TableArn": "arn:aws:dynamodb:ap-southeast-2:437313072050:table/testNonEncrypt", "ItemCount": 0, "CreationDateTime": 1583296041.861}}
MOCK_COMP = {"Table": {"TableArn": "arn:aws:dynamodb:ap-southeast-2:437313072050:table/test123", "SSEDescription": {"Status": "UPDATING", "KMSMasterKeyArn": "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6", "SSEType": "KMS"}}}
MOCK_CONF_ITEM = {"configuration": {"tableName": "test123", "tableStatus": "ACTIVE"}}
MOCK_CONF_ITEM_NON = {"configuration": {"tableName": "testNonEncrypt", "tableStatus": "ACTIVE"}}
MOCK_CONF_ITEM_NA = {"configuration": {"tableName": "testNA", "tableStatus": "DELETED"}}

def mock_get_client(client_name, *args, **kwargs):
    if client_name == 'dynamodb':
        return DB_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    def setUp(self):
        pass
    def test_compliant_user(self):
        DB_CLIENT_MOCK.describe_table.return_value = MOCK_COMP
        response = RULE.evaluate_change("", CLIENT_FACTORY, MOCK_CONF_ITEM, "")
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_non_compliant_user(self):
        DB_CLIENT_MOCK.describe_table.return_value = MOCK_NON_COMP
        response = RULE.evaluate_change("", CLIENT_FACTORY, MOCK_CONF_ITEM_NON, "")
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_na_compliant_user(self):
        DB_CLIENT_MOCK.describe_table.return_value = MOCK_NON_COMP
        response = RULE.evaluate_change("", CLIENT_FACTORY, MOCK_CONF_ITEM_NA, "")
        resp_expected = [
            Evaluation(ComplianceType.NOT_APPLICABLE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_all(self):
        pass
