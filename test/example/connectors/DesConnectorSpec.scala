/*
 * Copyright 2022 HM Revenue & Customs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package example.connectors

import example.config.AppConfig
import example.connectors.DesConnector
import example.utils.TestUtils
import uk.gov.hmrc.http.HeaderNames._
import uk.gov.hmrc.http.{Authorization, HeaderCarrier, SessionId}

class DesConnectorSpec extends TestUtils{

  class FakeConnector(override val appConfig: AppConfig) extends DesConnector {
    def headerCarrierTest(url: String)(hc: HeaderCarrier): HeaderCarrier = desHeaderCarrier(url)(hc)
  }
  val connector = new FakeConnector(appConfig = mockAppConfig)

  "FakeConnector" when {

    "base url is requested" should {
      "return the app config value" in {
        connector.baseUrl mustBe mockAppConfig.desBaseUrl
      }
    }

    "host is Internal" should {
      val internalHost = "http://localhost"

      "add the correct authorization" in {
        val hc = HeaderCarrier()
        val result = connector.headerCarrierTest(internalHost)(hc)
        result.authorization mustBe Some(Authorization(s"Bearer ${mockAppConfig.authorisationToken}"))
      }

      "add the correct environment" in {
        val hc = HeaderCarrier()
        val result = connector.headerCarrierTest(internalHost)(hc)
        result.extraHeaders mustBe List(
          "Environment" -> mockAppConfig.environment
        )
      }
    }

    "host is External" should {
      val externalHost = "http://127.0.0.1"

      "include all HeaderCarrier headers in the extraHeaders when the host is external" in {
        val hc = HeaderCarrier(sessionId = Some(SessionId("sessionIdHeaderValue")))
        val result = connector.headerCarrierTest(externalHost)(hc)

        result.extraHeaders.size mustBe  4
        result.extraHeaders.contains(xSessionId -> "sessionIdHeaderValue") mustBe true
        result.extraHeaders.contains(authorisation -> s"Bearer ${mockAppConfig.authorisationToken}") mustBe true
        result.extraHeaders.contains("Environment" -> mockAppConfig.environment) mustBe true
        result.extraHeaders.exists(x => x._1.equalsIgnoreCase(xRequestChain)) mustBe true
      }
    }
  }

}
