'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  DYNAMODB_TABLE_ENCRYPTED_KMS

Description:
  Check whether DynamoDB Table is encrypted with KMS.

Rationale:
  Encrypting on Dynamo ensure that no data is written on disk in clear text.

Indicative Severity:
  Medium

Trigger:
  Configuration Change on AWS::DynamoDB::Table

Reports on:
  AWS::DynamoDB::Table

Rule Parameters:
  None

Scenarios:
  Scenario: 1
    Given: DynamoDB table is not active state
     Then: Return NOT_APPLICABLE
  Scenario: 2
    Given: DynamoDB table is active
      And: DynamoDB table is encrypted with KMS
     Then: Return COMPLIANT
  Scenario: 3
    Given: DynamoDB table is active
      And: DynamoDB table is not encrypted with KMS
     Then: Return NON_COMPLIANT
'''

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType

class DYNAMODB_TABLE_ENCRYPTED_KMS(ConfigRule):
    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        dynamodb_client = client_factory.build_client('dynamodb')
        if configuration_item['configuration']['tableStatus'] != 'ACTIVE':
            return [Evaluation(ComplianceType.NOT_APPLICABLE)]
        response = dynamodb_client.describe_table(TableName=configuration_item['configuration']['tableName'])
        if 'SSEDescription' in  response['Table']:
            if response['Table']['SSEDescription']['SSEType'] == 'KMS':
                return [Evaluation(ComplianceType.COMPLIANT)]
            return [Evaluation(ComplianceType.NON_COMPLIANT)]
        return [Evaluation(ComplianceType.NON_COMPLIANT)]

def lambda_handler(event, context):
    my_rule = DYNAMODB_TABLE_ENCRYPTED_KMS()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
