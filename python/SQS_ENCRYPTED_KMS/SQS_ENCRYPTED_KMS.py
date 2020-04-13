"""
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  SQS_ENCRYPTED_KMS

Description:
  Check whether Amazon Simple Queue Service (Amazon SQS) is encrypted with AWS Key Management Service (AWS KMS).

Rationale:
  Encryption using AWS KMS provides protection at rest for the data stored in Amazon SQS queue.

Indicative Severity:
  Medium

Trigger:
  Configuration Change on AWS::SQS::Queue

Reports on:
  AWS::SQS::Queue
Rule Parameters:(optional)
  Provide comma seperated AWS KMS Key ARN list.

Scenarios:
  Scenario: 1
     Given: Rules parameter is provided
       And: Any key in "KmsKeyArns" is invalid
      Then: Return ERROR
  Scenario: 2
     Given: Rules parameter is provided
       And: All keys in "KmsKeyArns" is valid
      Then: Return Success
  Scenario: 3
    Given: Amazon SQS Queue is active
      And: Amazon SQS Queue is encrypted with KMS key
     Then: Return COMPLIANT
  Scenario: 4
    Given: Amazon SQS Queue is active
      And: Amazon SQS Queue is not encrypted with KMS key
     Then: Return NON_COMPLIANT
  Scenario: 5
    Given: Amazon SQS Queue is active
      And: Amazon SQS Queue is encrypted with KMS key
      And: KmsKeyArns Rule Parameter provided
     Then: Return COMPLIANT
  Scenario: 6
    Given: Amazon SQS Queue is active
      And: Amazon SQS Queue is not encrypted with KMS key
      And: KmsKeyArns Rule Parameter provided
     Then: Return NON_COMPLIANT
"""

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType, InvalidParametersError

class SQS_ENCRYPTED_KMS(ConfigRule):
    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        print(configuration_item)
        kms_key = configuration_item.get('configuration').get('KmsMasterKeyId')
        kms_arn_list = valid_rule_parameters.get("KmsKeyArns")
        if kms_key:
            if not kms_arn_list or kms_key in kms_arn_list:
                return [Evaluation(ComplianceType.COMPLIANT)]
            return [Evaluation(ComplianceType.NON_COMPLIANT, annotation="AWS KMS key '{}' used to encrypt the Amazon SQS Queue is not in rule_paramter 'KmsKeyArns'".format(kms_key))]
        return [Evaluation(ComplianceType.NON_COMPLIANT,
                           annotation="Amazon SQS queue is not encrypted with KMS")]

    def evaluate_parameters(self, rule_parameters):
        valid_rule_parameters = {}
        if 'KmsKeyArns' in rule_parameters:
            kms_key_arns = "".join(rule_parameters['KmsKeyArns'].split())
            if kms_key_arns:
                kms_key_arns = kms_key_arns.split(',')
                for kms_key_arn in kms_key_arns:
                    if not kms_key_arn.startswith('arn:aws:kms:'):
                        raise InvalidParametersError('Invalid AWS KMS Key Arn format for "{}". AWS KMS Key Arn starts with "arn:aws:kms:"'.format(kms_key_arn))
                valid_rule_parameters['KmsKeyArns'] = kms_key_arns
        return valid_rule_parameters


def lambda_handler(event, context):
    my_rule = SQS_ENCRYPTED_KMS()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
