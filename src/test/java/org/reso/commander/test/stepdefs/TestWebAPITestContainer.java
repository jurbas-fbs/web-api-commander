package org.reso.commander.test.stepdefs;

import io.cucumber.java8.En;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reso.commander.certfication.containers.WebAPITestContainer;
import org.reso.commander.common.TestUtils;
import org.reso.models.Settings;

import java.io.File;
import java.net.URL;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static io.restassured.path.json.JsonPath.from;
import static org.junit.Assert.*;
import static org.reso.commander.common.ErrorMsg.getDefaultErrorMessage;
import static org.reso.commander.common.TestUtils.JSON_VALUE_PATH;
import static org.reso.commander.common.TestUtils.parseTimestampFromEdmDateTimeOffsetString;

public class TestWebAPITestContainer implements En {
  private static final Logger LOG = LogManager.getLogger(TestWebAPITestContainer.class);
  AtomicReference<WebAPITestContainer> testContainer = new AtomicReference<>();

  public TestWebAPITestContainer() {

    /*
     * Background
     */
    Given("^a Web API test container was created using the RESOScript \"([^\"]*)\"$", (String fileName) -> {
      try {
        //get settings from mock RESOScript file
        URL resource = getClass().getClassLoader().getResource(fileName);
        assertNotNull(getDefaultErrorMessage("was unable to find the given RESOScript:", fileName), resource);

        setTestContainer(new WebAPITestContainer());
        getTestContainer().setSettings(Settings.loadFromRESOScript(new File(resource.getFile())));
        assertNotNull(getDefaultErrorMessage("could not load mock RESOScript: " + resource.getFile()), getTestContainer().getSettings());

        getTestContainer().initialize();
      } catch (Exception ex) {
        fail(getDefaultErrorMessage(ex));
      }
    });

    And("^sample metadata from \"([^\"]*)\" are loaded into the test container$", (String resourceName) -> {
      assertNotNull(getDefaultErrorMessage("resourceName cannot be null!"), resourceName);

      try {
        String xmlMetadataString = loadResourceAsString(resourceName);
        assertNotNull(getDefaultErrorMessage("could not load resourceName:", resourceName), xmlMetadataString);
        getTestContainer().setResponseCode(HttpStatus.SC_OK);

        getTestContainer().setXMLResponseData(xmlMetadataString);
      } catch (Exception ex) {
        fail(getDefaultErrorMessage(ex));
      }
    });


    /*
     * Auth settings validation
     */
    When("^an auth token is provided in \"([^\"]*)\"$", (String clientSettingsAuthToken) -> {
      String token = Settings.resolveParametersString(clientSettingsAuthToken, getTestContainer().getSettings());
      assertNotNull(getDefaultErrorMessage("BearerToken is null in the ClientSettings section!"), token);
    });

    Then("^the Commander is created using auth token client mode$", () -> {
      assertTrue(getDefaultErrorMessage("expected auth token Commander client!"),
          getTestContainer().getCommander().isAuthTokenClient());
    });

    And("^the auth token has a value of \"([^\"]*)\"$", (String assertedTokenValue) -> {
      assertEquals(getDefaultErrorMessage("asserted token value is not equal to the one provided in the container!"),
          assertedTokenValue, getTestContainer().getAuthToken());
    });

    And("^a Commander instance exists within the test container$", () -> {
      assertNotNull(getDefaultErrorMessage("Commander instance is null in the container!"),
          getTestContainer().getCommander());
    });

    But("^the Commander is not created using client credentials mode$", () -> {
      assertFalse(getDefaultErrorMessage("expected that the Commander was not using client credentials"),
          getTestContainer().getCommander().isOAuth2Client());
    });

    And("^Settings are present in the test container$", () -> {
      assertNotNull(getDefaultErrorMessage("settings were not found in the Web API test container!"),
          getTestContainer().getSettings());
    });


    /*
     * Metadata validation
     */
    Then("^metadata are valid$", () -> {
      getTestContainer().validateMetadata();
      assertTrue(getDefaultErrorMessage("getIsMetadataValid() returned false when true was expected!"),
          getTestContainer().hasValidMetadata());
    });

    Then("^metadata are invalid$", () -> {
      getTestContainer().validateMetadata();
      assertFalse(getDefaultErrorMessage("getIsMetadataValid() returned true when false was expected!"),
          getTestContainer().hasValidMetadata());
    });


    /*
     * DataSystem validation
     */
    When("^sample JSON data from \"([^\"]*)\" are loaded into the test container$", (String resourceName) -> {
      getTestContainer().setResponseCode(HttpStatus.SC_OK);
      getTestContainer().setResponseData(loadResourceAsString(resourceName));
    });

    Then("^schema validation passes for the sample DataSystem data$", () -> {
      assertTrue(getDefaultErrorMessage("expected DataSystem to pass validation, but it failed!"),
          getTestContainer().validateDataSystem().getIsValidDataSystem());
    });

    Then("^schema validation fails for the sample DataSystem data$", () -> {
      assertFalse(getDefaultErrorMessage("expected DataSystem to fail validation, but it passed!"),
          getTestContainer().validateDataSystem().getIsValidDataSystem());
    });


    /*
     * Integer Response Testing
     */
    Then("^Integer comparisons of \"([^\"]*)\" \"([^\"]*)\" (\\d+) return \"([^\"]*)\"$", (String fieldName, String op, Integer assertedValue, String expectedValue) -> {
      final boolean expected = Boolean.parseBoolean(expectedValue),
          result = testIntegerComparisons(fieldName, op, assertedValue);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    });

    Then("^Integer comparisons of \"([^\"]*)\" \"([^\"]*)\" null return \"([^\"]*)\"$", (String fieldName, String op, String expectedValue) -> {
      final boolean expected = Boolean.parseBoolean(expectedValue),
          result = testIntegerComparisons(fieldName, op, null);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    });


    /*
     * String Response Testing
     */
    Then("^String data in \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" returns \"([^\"]*)\"$", (String fieldName, String op, String assertedValue, String expectedValue) -> {
      final boolean expected = Boolean.parseBoolean(expectedValue),
          result = testStringComparisons(fieldName, op, assertedValue);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    });

    Then("^String data in \"([^\"]*)\" \"([^\"]*)\" null returns \"([^\"]*)\"$", (String fieldName, String op, String expectedValue) -> {
      final boolean expected = Boolean.parseBoolean(expectedValue),
          result = testStringComparisons(fieldName, op, null);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    });

    Then("^String data in \"([^\"]*)\" \"([^\"]*)\" equals \"([^\"]*)\"$", (String fieldName, String op, String assertedValue) -> {
      assertTrue(testStringComparisons(fieldName, op, assertedValue));
    });

    Then("^String data in \"([^\"]*)\" \"([^\"]*)\" does not equal \"([^\"]*)\"$", (String fieldName, String op, String assertedValue) -> {
      assertFalse(testStringComparisons(fieldName, op, assertedValue));
    });

    Then("^String data in \"([^\"]*)\" \"([^\"]*)\" is null$", (String fieldName, String op) -> {
      assertFalse(testStringComparisons(fieldName, op, null));
    });


    /*
     * Timestamp Response Testing
     */
    Then("^Timestamp comparisons of \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" return \"([^\"]*)\"$", (String fieldName, String op, String assertedValue, String expectedValue) -> {
      final boolean expected = Boolean.parseBoolean(expectedValue),
          result = testTimestampComparisons(fieldName, op, assertedValue);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    });

    Then("^Timestamp comparisons of \"([^\"]*)\" \"([^\"]*)\" null return \"([^\"]*)\"$", (String fieldName, String op, String expectedValue) -> {
      final boolean expected = Boolean.parseBoolean(expectedValue),
          result = testTimestampComparisons(fieldName, op, null);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    });


    /*
     * Date Part Response Testing
     */
    Then("^\"([^\"]*)\" comparisons of \"([^\"]*)\" \"([^\"]*)\" (\\d+) return \"([^\"]*)\"$", (String datePart, String fieldName, String op, Integer assertedValue, String expectedValue) -> {
      final boolean expected = Boolean.parseBoolean(expectedValue),
          result = testDatePartComparisons(datePart, fieldName, op, assertedValue);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    });

    Then("^\"([^\"]*)\" comparisons of \"([^\"]*)\" \"([^\"]*)\" null return \"([^\"]*)\"$", (String datePart, String fieldName, String op, String expectedValue) -> {
      final boolean expected = Boolean.parseBoolean(expectedValue),
          result = testDatePartComparisons(datePart, fieldName, op, null);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    });
  }

  boolean testStringComparisons(String fieldName, String op, String assertedValue) {
    AtomicBoolean result = new AtomicBoolean(false);
    //iterate over the items and count the number of fields with data to determine whether there are data present
    from(getTestContainer().getResponseData()).getList(JSON_VALUE_PATH, HashMap.class).forEach(item -> {
      result.compareAndSet(result.get(), TestUtils.compare((String)item.get(fieldName), op, assertedValue));
    });
    return result.get();
  }

  boolean testIntegerComparisons(String fieldName, String op, Integer assertedValue) {
    AtomicBoolean result = new AtomicBoolean(false);
    //iterate over the items and count the number of fields with data to determine whether there are data present
    from(getTestContainer().getResponseData()).getList(JSON_VALUE_PATH, HashMap.class).forEach(item -> {
      result.compareAndSet(result.get(), TestUtils.compare((Integer) item.get(fieldName), op, assertedValue));
    });
    return result.get();
  }

  boolean testTimestampComparisons(String fieldName, String op, String offsetDateTime) {
    AtomicBoolean result = new AtomicBoolean(false);
    //iterate over the items and count the number of fields with data to determine whether there are data present
    from(getTestContainer().getResponseData()).getList(JSON_VALUE_PATH, HashMap.class).forEach(item -> {
      try {
        result.compareAndSet(result.get(), TestUtils.compare(
            parseTimestampFromEdmDateTimeOffsetString((String)item.get(fieldName)), op,
            parseTimestampFromEdmDateTimeOffsetString(offsetDateTime)));
      } catch (Exception ex) {
        fail(getDefaultErrorMessage(ex));
      }
    });
    return result.get();
  }

  boolean testDatePartComparisons(String datePart, String fieldName, String op, Integer assertedValue) {
    AtomicBoolean result = new AtomicBoolean(false);

    from(getTestContainer().getResponseData()).getList(JSON_VALUE_PATH, HashMap.class).forEach(item -> {
          try {
            result.compareAndSet(result.get(), TestUtils.compare(TestUtils.getTimestampPart(datePart, item.get(fieldName)), op, assertedValue));
          } catch (Exception ex) {
            fail(getDefaultErrorMessage(ex));
    }});
    return result.get();
  }

  /**
   * Returns a string containing the contents of the given resource name
   * @param resourceName the resource name to load
   * @return string data from the resource
   */
  public String loadResourceAsString(String resourceName) {
    return TestUtils.convertInputStreamToString(getClass().getClassLoader().getResourceAsStream(resourceName));
  }

  private WebAPITestContainer getTestContainer() {
    return testContainer.get();
  }

  private void setTestContainer(WebAPITestContainer testContainer) {
    this.testContainer.set(testContainer);
  }
}