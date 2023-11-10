# This file was autogenerated on: 2023110900245888
Feature: SocialMedia

  Background:
    Given a RESOScript or Metadata file are provided
    When a RESOScript file is provided
    Then Client Settings and Parameters can be read from the RESOScript
    And a test container was successfully created from the given RESOScript file
    And the test container uses an Authorization Code or Client Credentials for authentication
    And valid metadata were retrieved from the server
    When a metadata file is provided
    Then a test container was successfully created from the given metadata file
    And valid metadata are loaded into the test container

  @SocialMedia @dd-1.7
  Scenario: ClassName
    When "ClassName" exists in the "SocialMedia" metadata
    Then "ClassName" MUST be "Single Enumeration" data type

  @SocialMedia @dd-1.7
  Scenario: ModificationTimestamp
    Given that the following synonyms for "ModificationTimestamp" DO NOT exist in the "SocialMedia" metadata
      | ModificationDateTime |
      | DateTimeModified |
      | ModDate |
      | DateMod |
      | UpdateDate |
      | UpdateTimestamp |
    When "ModificationTimestamp" exists in the "SocialMedia" metadata
    Then "ModificationTimestamp" MUST be "Timestamp" data type

  @SocialMedia @dd-1.7
  Scenario: ResourceName
    When "ResourceName" exists in the "SocialMedia" metadata
    Then "ResourceName" MUST be "Single Enumeration" data type

  @SocialMedia @dd-1.7
  Scenario: ResourceRecordID
    Given that the following synonyms for "ResourceRecordID" DO NOT exist in the "SocialMedia" metadata
      | MLNumber |
      | MLSNumber |
      | ListingNumber |
      | AgentID |
      | OfficeID |
      | ContactID |
    When "ResourceRecordID" exists in the "SocialMedia" metadata
    Then "ResourceRecordID" MUST be "String" data type
    And "ResourceRecordID" length SHOULD be equal to the RESO Suggested Max Length of 255

  @SocialMedia @dd-1.7
  Scenario: ResourceRecordKey
    Given that the following synonyms for "ResourceRecordKey" DO NOT exist in the "SocialMedia" metadata
      | SystemUniqueID |
      | ImmediateSourceID |
    When "ResourceRecordKey" exists in the "SocialMedia" metadata
    Then "ResourceRecordKey" MUST be "String" data type
    And "ResourceRecordKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @SocialMedia @dd-1.7
  Scenario: SocialMediaKey
    Given that the following synonyms for "SocialMediaKey" DO NOT exist in the "SocialMedia" metadata
      | SystemUniqueID |
      | ImmediateSourceID |
    When "SocialMediaKey" exists in the "SocialMedia" metadata
    Then "SocialMediaKey" MUST be "String" data type
    And "SocialMediaKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @SocialMedia @dd-1.7
  Scenario: SocialMediaType
    Given that the following synonyms for "SocialMediaType" DO NOT exist in the "SocialMedia" metadata
      | MimeType |
    When "SocialMediaType" exists in the "SocialMedia" metadata
    Then "SocialMediaType" MUST be "Single Enumeration" data type

  @SocialMedia @dd-1.7
  Scenario: SocialMediaUrlOrId
    When "SocialMediaUrlOrId" exists in the "SocialMedia" metadata
    Then "SocialMediaUrlOrId" MUST be "String" data type
    And "SocialMediaUrlOrId" length SHOULD be equal to the RESO Suggested Max Length of 8000
