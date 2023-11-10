# This file was autogenerated on: 20231109002504917
Feature: Showing

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

  @Showing @dd-2.0
  Scenario: AgentOriginatingSystemID
    When "AgentOriginatingSystemID" exists in the "Showing" metadata
    Then "AgentOriginatingSystemID" MUST be "String" data type
    And "AgentOriginatingSystemID" length SHOULD be equal to the RESO Suggested Max Length of 25

  @Showing @dd-2.0
  Scenario: AgentOriginatingSystemName
    When "AgentOriginatingSystemName" exists in the "Showing" metadata
    Then "AgentOriginatingSystemName" MUST be "String" data type
    And "AgentOriginatingSystemName" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: AgentSourceSystemID
    When "AgentSourceSystemID" exists in the "Showing" metadata
    Then "AgentSourceSystemID" MUST be "String" data type
    And "AgentSourceSystemID" length SHOULD be equal to the RESO Suggested Max Length of 25

  @Showing @dd-2.0
  Scenario: AgentSourceSystemName
    When "AgentSourceSystemName" exists in the "Showing" metadata
    Then "AgentSourceSystemName" MUST be "String" data type
    And "AgentSourceSystemName" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ListingId
    When "ListingId" exists in the "Showing" metadata
    Then "ListingId" MUST be "String" data type
    And "ListingId" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ListingKey
    When "ListingKey" exists in the "Showing" metadata
    Then "ListingKey" MUST be "String" data type
    And "ListingKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ListingOriginatingSystemID
    When "ListingOriginatingSystemID" exists in the "Showing" metadata
    Then "ListingOriginatingSystemID" MUST be "String" data type
    And "ListingOriginatingSystemID" length SHOULD be equal to the RESO Suggested Max Length of 25

  @Showing @dd-2.0
  Scenario: ListingOriginatingSystemName
    When "ListingOriginatingSystemName" exists in the "Showing" metadata
    Then "ListingOriginatingSystemName" MUST be "String" data type
    And "ListingOriginatingSystemName" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ListingSourceSystemID
    When "ListingSourceSystemID" exists in the "Showing" metadata
    Then "ListingSourceSystemID" MUST be "String" data type
    And "ListingSourceSystemID" length SHOULD be equal to the RESO Suggested Max Length of 25

  @Showing @dd-2.0
  Scenario: ListingSourceSystemName
    When "ListingSourceSystemName" exists in the "Showing" metadata
    Then "ListingSourceSystemName" MUST be "String" data type
    And "ListingSourceSystemName" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ModificationTimestamp
    When "ModificationTimestamp" exists in the "Showing" metadata
    Then "ModificationTimestamp" MUST be "Timestamp" data type

  @Showing @dd-2.0
  Scenario: OriginalEntryTimestamp
    When "OriginalEntryTimestamp" exists in the "Showing" metadata
    Then "OriginalEntryTimestamp" MUST be "Timestamp" data type

  @Showing @dd-2.0
  Scenario: OriginatingSystemAgentKey
    When "OriginatingSystemAgentKey" exists in the "Showing" metadata
    Then "OriginatingSystemAgentKey" MUST be "String" data type
    And "OriginatingSystemAgentKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: OriginatingSystemListingKey
    When "OriginatingSystemListingKey" exists in the "Showing" metadata
    Then "OriginatingSystemListingKey" MUST be "String" data type
    And "OriginatingSystemListingKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: OriginatingSystemShowingKey
    When "OriginatingSystemShowingKey" exists in the "Showing" metadata
    Then "OriginatingSystemShowingKey" MUST be "String" data type
    And "OriginatingSystemShowingKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ShowingAgentKey
    When "ShowingAgentKey" exists in the "Showing" metadata
    Then "ShowingAgentKey" MUST be "String" data type
    And "ShowingAgentKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ShowingAgentMlsID
    When "ShowingAgentMlsID" exists in the "Showing" metadata
    Then "ShowingAgentMlsID" MUST be "String" data type
    And "ShowingAgentMlsID" length SHOULD be equal to the RESO Suggested Max Length of 25

  @Showing @dd-2.0
  Scenario: ShowingAllowed
    When "ShowingAllowed" exists in the "Showing" metadata
    Then "ShowingAllowed" MUST be "Boolean" data type

  @Showing @dd-2.0
  Scenario: ShowingEndTimestamp
    When "ShowingEndTimestamp" exists in the "Showing" metadata
    Then "ShowingEndTimestamp" MUST be "Timestamp" data type

  @Showing @dd-2.0
  Scenario: ShowingId
    When "ShowingId" exists in the "Showing" metadata
    Then "ShowingId" MUST be "String" data type
    And "ShowingId" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ShowingKey
    When "ShowingKey" exists in the "Showing" metadata
    Then "ShowingKey" MUST be "String" data type
    And "ShowingKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ShowingOriginatingSystemID
    When "ShowingOriginatingSystemID" exists in the "Showing" metadata
    Then "ShowingOriginatingSystemID" MUST be "String" data type
    And "ShowingOriginatingSystemID" length SHOULD be equal to the RESO Suggested Max Length of 25

  @Showing @dd-2.0
  Scenario: ShowingOriginatingSystemName
    When "ShowingOriginatingSystemName" exists in the "Showing" metadata
    Then "ShowingOriginatingSystemName" MUST be "String" data type
    And "ShowingOriginatingSystemName" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ShowingRequestedTimestamp
    When "ShowingRequestedTimestamp" exists in the "Showing" metadata
    Then "ShowingRequestedTimestamp" MUST be "Timestamp" data type

  @Showing @dd-2.0
  Scenario: ShowingSourceSystemID
    When "ShowingSourceSystemID" exists in the "Showing" metadata
    Then "ShowingSourceSystemID" MUST be "String" data type
    And "ShowingSourceSystemID" length SHOULD be equal to the RESO Suggested Max Length of 25

  @Showing @dd-2.0
  Scenario: ShowingSourceSystemName
    When "ShowingSourceSystemName" exists in the "Showing" metadata
    Then "ShowingSourceSystemName" MUST be "String" data type
    And "ShowingSourceSystemName" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: ShowingStartTimestamp
    When "ShowingStartTimestamp" exists in the "Showing" metadata
    Then "ShowingStartTimestamp" MUST be "Timestamp" data type

  @Showing @dd-2.0
  Scenario: ShowingStatus
    When "ShowingStatus" exists in the "Showing" metadata
    Then "ShowingStatus" MUST be "Single Enumeration" data type

  @Showing @dd-2.0
  Scenario: ShowingTimeZone
    When "ShowingTimeZone" exists in the "Showing" metadata
    Then "ShowingTimeZone" MUST be "Single Enumeration" data type

  @Showing @dd-2.0
  Scenario: ShowingUrl
    When "ShowingUrl" exists in the "Showing" metadata
    Then "ShowingUrl" MUST be "String" data type
    And "ShowingUrl" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: SourceSystemAgentKey
    When "SourceSystemAgentKey" exists in the "Showing" metadata
    Then "SourceSystemAgentKey" MUST be "String" data type
    And "SourceSystemAgentKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: SourceSystemListingKey
    When "SourceSystemListingKey" exists in the "Showing" metadata
    Then "SourceSystemListingKey" MUST be "String" data type
    And "SourceSystemListingKey" length SHOULD be equal to the RESO Suggested Max Length of 255

  @Showing @dd-2.0
  Scenario: SourceSystemShowingKey
    When "SourceSystemShowingKey" exists in the "Showing" metadata
    Then "SourceSystemShowingKey" MUST be "String" data type
    And "SourceSystemShowingKey" length SHOULD be equal to the RESO Suggested Max Length of 255
