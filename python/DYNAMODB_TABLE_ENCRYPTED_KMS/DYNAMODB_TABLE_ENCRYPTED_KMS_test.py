import unittest
from mock import patch, MagicMock
from rdklib import Evaluation, ComplianceType, InvalidParametersError
import rdklibtest

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::DynamoDB::Table'
MODULE = __import__('DYNAMODB_TABLE_ENCRYPTED_KMS')
RULE = MODULE.DYNAMODB_TABLE_ENCRYPTED_KMS()
CLIENT_FACTORY = MagicMock()
DB_CLIENT_MOCK = MagicMock()
CONFIG_CLIENT = MagicMock()

def mock_get_client(service, *args, **kwargs):
    if service == 'dynamodb':
        return DB_CLIENT_MOCK
    if service == 'config':
        return CONFIG_CLIENT
    raise Exception("Attempting to create an unknown client")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):
    MOCK_CONF_ITEM = {"configuration": {"tableName": "testNonEncrypt", "tableStatus": "ACTIVE", "ssedescription": {"status": "ENABLED", "ssetype": "KMS", "kmsmasterKeyArn": "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6"}}}
    MOCK_CONF_ITEM_NON = {"configuration": {"tableName": "table123", "tableStatus": "ACTIVE"}}
    MOCK_CONF_ITEM_NA = {"configuration": {"tableName": "testNA", "tableStatus": "DELETED"}}
    MOCK_NON_COMP = {"Table": {"TableArn": "arn:aws:dynamodb:ap-southeast-2:437313072050:table/testNonEncrypt", "ItemCount": 0, "CreationDateTime": 1583296041.861}}
    MOCK_COMP = {"Table": {"TableArn": "arn:aws:dynamodb:ap-southeast-2:437313072050:table/test123", "SSEDescription": {"Status": "UPDATING", "KMSMasterKeyArn": "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6", "SSEType": "KMS"}}}

    def test_emptyruleparameter_returnsuccess(self):
        rule_invalid_parameter = {
            "KmsKeyArns":  ""
        }
        response = RULE.evaluate_parameters(rule_invalid_parameter)
        self.assertEqual(response, {})

    def test_scenario1_invalidruleparameter_returnserror(self):
        rule_invalid_parameter = {
            "KmsKeyArns":  "invalid-arn,arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6"
        }
        with self.assertRaises(InvalidParametersError) as context:
            RULE.evaluate_parameters(rule_invalid_parameter)
        self.assertIn('Invalid AWS KMS Key Arn format for "invalid-arn". AWS KMS Key Arn starts with "arn:aws:kms:"', str(context.exception))

    def test_scenario2_evaluateparameters_validruleparameter_returnsuccess(self):
        rule_valid_parameter = {
            "KmsKeyArns":  "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6,arn:aws:kms:ap-southeast-2:437313072050:key/ff61230d-5aa3-4ece-9532-a97fecb51f36"
        }

        resp_expected = {
            "KmsKeyArns": [
                "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6",
                "arn:aws:kms:ap-southeast-2:437313072050:key/ff61230d-5aa3-4ece-9532-a97fecb51f36"
            ]
        }
        response = RULE.evaluate_parameters(rule_valid_parameter)
        self.assertEqual(response, resp_expected)

    def test_scenario3_config_not_applicable_table(self):
        response = RULE.evaluate_change("", CLIENT_FACTORY, self.MOCK_CONF_ITEM_NA, {})
        resp_expected = [
            Evaluation(ComplianceType.NOT_APPLICABLE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario4_non_compliant_table(self):
        response = RULE.evaluate_change("", CLIENT_FACTORY, self.MOCK_CONF_ITEM_NON, {})
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, annotation="Amazon DynamoDB Table is not encrypted with KMS")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario5_compliant_table(self):
        response = RULE.evaluate_change("", CLIENT_FACTORY, self.MOCK_CONF_ITEM, {})
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario6_compliant_table_with_params(self):
        valid_rule_parameter = {
            "KmsKeyArns": [
                "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6",
                "arn:aws:kms:ap-southeast-2:437313072050:key/ff61230d-5aa3-4ece-9532-a97fecb51f36"
            ]
        }
        response = RULE.evaluate_change("", CLIENT_FACTORY, self.MOCK_CONF_ITEM, valid_rule_parameter)
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario7_non_compliant_table_with_params(self):
        valid_rule_parameter = {
            "KmsKeyArns": [
                "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6",
                "arn:aws:kms:ap-southeast-2:437313072050:key/ff61230d-5aa3-4ece-9532-a97fecb51f36"
            ]
        }
        response = RULE.evaluate_change("", CLIENT_FACTORY, self.MOCK_CONF_ITEM_NON, valid_rule_parameter)
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, annotation="Amazon DynamoDB Table is not encrypted with KMS")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario4_periodic_non_compliant_table(self):
        CONFIG_CLIENT.select_resource_config.return_value = {"Results":['{"resourceName":"test123"}']}
        DB_CLIENT_MOCK.describe_table.return_value = self.MOCK_NON_COMP
        response = RULE.evaluate_periodic("", CLIENT_FACTORY, {})
        resp_expected = [Evaluation(ComplianceType.NON_COMPLIANT, 'test123', RESOURCE_TYPE, annotation="Table is not encrypted with KMS")]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario5_periodic_compliant_table(self):
        CONFIG_CLIENT.select_resource_config.return_value = {"Results":['{"resourceName":"testNonEncrypt"}']}
        DB_CLIENT_MOCK.describe_table.return_value = self.MOCK_COMP
        response = RULE.evaluate_periodic("", CLIENT_FACTORY, {})
        resp_expected = [Evaluation(ComplianceType.COMPLIANT, 'testNonEncrypt', RESOURCE_TYPE)]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario6_periodic_non_compliant_table_with_params(self):
        valid_rule_parameter = {
            "KmsKeyArns": [
                "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6",
                "arn:aws:kms:ap-southeast-2:437313072050:key/ff61230d-5aa3-4ece-9532-a97fecb51f36"
            ]
        }
        CONFIG_CLIENT.select_resource_config.return_value = {"Results":['{"resourceName":"test123"}']}
        DB_CLIENT_MOCK.describe_table.return_value = self.MOCK_NON_COMP
        response = RULE.evaluate_periodic("", CLIENT_FACTORY, valid_rule_parameter)
        resp_expected = [Evaluation(ComplianceType.NON_COMPLIANT, 'test123', RESOURCE_TYPE, annotation="Table is not encrypted with KMS")]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario7_periodic_compliant_table_with_params(self):
        valid_rule_parameter = {
            "KmsKeyArns": [
                "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6",
                "arn:aws:kms:ap-southeast-2:437313072050:key/ff61230d-5aa3-4ece-9532-a97fecb51f36"
            ]
        }
        CONFIG_CLIENT.select_resource_config.return_value = {"Results":['{"resourceName":"testNonEncrypt"}']}
        DB_CLIENT_MOCK.describe_table.return_value = self.MOCK_COMP
        response = RULE.evaluate_periodic("", CLIENT_FACTORY, valid_rule_parameter)
        resp_expected = [Evaluation(ComplianceType.COMPLIANT, 'testNonEncrypt', RESOURCE_TYPE)]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
