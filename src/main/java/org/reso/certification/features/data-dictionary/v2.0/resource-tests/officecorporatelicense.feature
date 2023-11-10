# This file was autogenerated on: 20231109002504917
Feature: OfficeCorporateLicense

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

  @OfficeCorporateLicense @dd-2.0
  Scenario: ModificationTimestamp
    When "ModificationTimestamp" exists in the "OfficeCorporateLicense" metadata
    Then "ModificationTimestamp" MUST be "Timestamp" data type

  @OfficeCorporateLicense @dd-2.0
  Scenario: OfficeCorporateLicense
    When "OfficeCorporateLicense" exists in the "OfficeCorporateLicense" metadata
    Then "OfficeCorporateLicense" MUST be "String" data type
    And "OfficeCorporateLicense" length SHOULD be equal to the RESO Suggested Max Length of 50

  @OfficeCorporateLicense @dd-2.0
  Scenario: OfficeCorporateLicenseExpirationDate
    When "OfficeCorporateLicenseExpirationDate" exists in the "OfficeCorporateLicense" metadata
    Then "OfficeCorporateLicenseExpirationDate" MUST be "Date" data type

  @OfficeCorporateLicense @dd-2.0
  Scenario: OfficeCorporateLicenseKey
    When "OfficeCorporateLicenseKey" exists in the "OfficeCorporateLicense" metadata
    Then "OfficeCorporateLicenseKey" MUST be "String" data type
    And "OfficeCorporateLicenseKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @OfficeCorporateLicense @dd-2.0
  Scenario: OfficeCorporateLicenseState
    When "OfficeCorporateLicenseState" exists in the "OfficeCorporateLicense" metadata
    Then "OfficeCorporateLicenseState" MUST be "Single Enumeration" data type

  @OfficeCorporateLicense @dd-2.0
  Scenario: OfficeCorporateLicenseType
    When "OfficeCorporateLicenseType" exists in the "OfficeCorporateLicense" metadata
    Then "OfficeCorporateLicenseType" MUST be "Single Enumeration" data type

  @OfficeCorporateLicense @dd-2.0
  Scenario: OfficeKey
    When "OfficeKey" exists in the "OfficeCorporateLicense" metadata
    Then "OfficeKey" MUST be "String" data type
    And "OfficeKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @OfficeCorporateLicense @dd-2.0
  Scenario: OfficeMlsId
    When "OfficeMlsId" exists in the "OfficeCorporateLicense" metadata
    Then "OfficeMlsId" MUST be "String" data type
    And "OfficeMlsId" length SHOULD be equal to the RESO Suggested Max Length of 25
