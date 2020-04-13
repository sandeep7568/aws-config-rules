'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  DYNAMODB_TABLE_ENCRYPTED_KMS

Description:
  Check whether Amazon DynamoDB Table is encrypted with KMS.

Rationale:
  Encrypting on Amazon DynamoDB tables ensure that no data is written on disk in clear text.

Indicative Severity:
  Medium

Trigger:
  Configuration Change on AWS::DynamoDB::Table

Reports on:
  AWS::DynamoDB::Table

Rule Parameters:(optional)
  Provide comma seperated KMS Key ARN list.

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
    Given: Amazon DynamoDB table is not active state
     Then: Return NOT_APPLICABLE
  Scenario: 4
    Given: Amazon DynamoDB table is active
      And: Amazon DynamoDB table is encrypted with KMS
     Then: Return COMPLIANT
  Scenario: 5
    Given: Amazon DynamoDB table is active
      And: Amazon DynamoDB table is not encrypted with KMS
     Then: Return NON_COMPLIANT
  Scenario: 6
    Given: Amazon DynamoDB table is active
      And: KmsKeyArns Rule Parameter provided
      And: Amazon DynamoDB table is encrypted with provided KmsKeyArns Rule Parameter
     Then: Return COMPLIANT
  Scenario: 7
    Given: Amazon DynamoDB table is active
      And: KmsKeyArns Rule Parameter provided
      And: Amazon DynamoDB table is not encrypted with with provided KmsKeyArns Rule Parameter
     Then: Return NON_COMPLIANT
'''
import json
from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType, InvalidParametersError
PAGE_SIZE = 100
DEFAULT_RESOURCE_TYPE = 'AWS::DynamoDB::Table'

class DYNAMODB_TABLE_ENCRYPTED_KMS(ConfigRule):
    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        evaluations = []
        config_client = client_factory.build_client(service='config')
        dynamodb_client = client_factory.build_client(service='dynamodb')
        for table in describe_tables(config_client):
            is_valid_enctyption = False
            annotation = ''
            table_data = dynamodb_client.describe_table(TableName=table)
            if 'SSEDescription' in table_data['Table']:
                ssetype = table_data['Table']['SSEDescription']['SSEType']
                kmskey = table_data['Table']['SSEDescription']['KMSMasterKeyArn']
                kms_arn_list = valid_rule_parameters.get("KmsKeyArns")
                if ssetype == 'KMS':
                    if not kms_arn_list or kmskey in kms_arn_list:
                        is_valid_enctyption = True
                    else:
                        is_valid_enctyption = False
                        annotation = "AWS KMS key '{}' used to encrypt the Amazon DynamoDB Table is not in rule_paramter 'KmsKeyArns'".format(kmskey)
                else:
                    annotation = "Table is not encrypted with KMS"
                    is_valid_enctyption = False
            else:
                annotation = "Table is not encrypted with KMS"
                is_valid_enctyption = False
            if is_valid_enctyption:
                evaluations.append(Evaluation(ComplianceType.COMPLIANT, table, DEFAULT_RESOURCE_TYPE))
            else:
                evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT,
                                              table, DEFAULT_RESOURCE_TYPE, annotation=annotation))
        return evaluations

    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        if configuration_item['configuration']['tableStatus'] != 'ACTIVE':
            return [Evaluation(ComplianceType.NOT_APPLICABLE)]

        if 'ssedescription' in configuration_item['configuration']:
            ssetype = configuration_item['configuration']['ssedescription']['ssetype']
            kmskey = configuration_item['configuration']['ssedescription']['kmsmasterKeyArn']
            kms_arn_list = valid_rule_parameters.get("KmsKeyArns")

            if ssetype == 'KMS':
                if not kms_arn_list or kmskey in kms_arn_list:
                    return [Evaluation(ComplianceType.COMPLIANT)]
                return [Evaluation(ComplianceType.NON_COMPLIANT, annotation="AWS KMS key '{}' used to encrypt the Amazon DynamoDB Table is not in rule_paramter 'KmsKeyArns'".format(kmskey))]
        return [Evaluation(ComplianceType.NON_COMPLIANT, annotation="Amazon DynamoDB Table is not encrypted with KMS")]

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

def describe_tables(config_client):
    sql = "select * where resourceType = 'AWS::DynamoDB::Table'"
    next_token = True
    response = config_client.select_resource_config(Expression=sql, Limit=PAGE_SIZE)
    while next_token:
        for result in response['Results']:
            yield json.loads(result)['resourceName']
        if 'NextToken' in response:
            next_token = response['NextToken']
            response = config_client.select_resource_config(Expression=sql, NextToken=next_token, Limit=PAGE_SIZE)
        else:
            next_token = False

def lambda_handler(event, context):
    my_rule = DYNAMODB_TABLE_ENCRYPTED_KMS()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
