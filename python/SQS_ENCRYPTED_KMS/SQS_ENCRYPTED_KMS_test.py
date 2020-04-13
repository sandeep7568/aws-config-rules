import unittest
from rdklib import Evaluation, ComplianceType, InvalidParametersError
import rdklibtest


MODULE = __import__('SQS_ENCRYPTED_KMS')
RULE = MODULE.SQS_ENCRYPTED_KMS()


class ComplianceTest(unittest.TestCase):

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

    def test_scenario3_queue_compliant(self):
        config_item = {"configuration": {"KmsMasterKeyId": "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6"}}
        response = RULE.evaluate_change({}, {}, config_item, {})
        expected_response = [Evaluation(ComplianceType.COMPLIANT)]
        rdklibtest.assert_successful_evaluation(self, response, expected_response)

    def test_scenario4_queue_non_compliant(self):
        config_item = {"configuration": {}}
        response = RULE.evaluate_change({}, {}, config_item, {})
        expected_response = [Evaluation(ComplianceType.NON_COMPLIANT,
                                        annotation="Amazon SQS queue is not encrypted with KMS")]
        rdklibtest.assert_successful_evaluation(self, response, expected_response)

    def test_scenario5_queue_compliant_params(self):
        valid_rule_parameter = {
            "KmsKeyArns": [
                "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6",
                "arn:aws:kms:ap-southeast-2:437313072050:key/ff61230d-5aa3-4ece-9532-a97fecb51f36"
            ]
        }
        config_item = {"configuration": {"KmsMasterKeyId": "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6"}}
        response = RULE.evaluate_change({}, {}, config_item, valid_rule_parameter)
        expected_response = [Evaluation(ComplianceType.COMPLIANT)]
        rdklibtest.assert_successful_evaluation(self, response, expected_response)

    def test_scenario6_queue_non_compliant_with_params(self):
        valid_rule_parameter = {
            "KmsKeyArns": [
                "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb0a6",
                "arn:aws:kms:ap-southeast-2:437313072050:key/ff61230d-5aa3-4ece-9532-a97fecb51f36"
            ]
        }
        config_item = {"configuration": {"KmsMasterKeyId": "arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb088"}}
        response = RULE.evaluate_change({}, {}, config_item, valid_rule_parameter)
        expected_response = [Evaluation(ComplianceType.NON_COMPLIANT,
                                        annotation="AWS KMS key 'arn:aws:kms:ap-southeast-2:437313072050:key/f4fb52b5-03a0-4397-a2db-cb5b94abb088' used to encrypt the Amazon SQS Queue is not in rule_paramter 'KmsKeyArns'")]
        rdklibtest.assert_successful_evaluation(self, response, expected_response)
