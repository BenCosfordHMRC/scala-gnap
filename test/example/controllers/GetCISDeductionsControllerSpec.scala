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

package example.controllers

import builders.CISSourceBuilder.{contractorCISSource, customerCISSource}
import example.controllers.GetCISDeductionsController
import example.models.{DesErrorBodyModel, DesErrorModel}
import example.models.get.AllCISDeductions
import example.services.CISDeductionsService
import org.scalamock.handlers.CallHandler4
import play.api.http.Status.{INTERNAL_SERVER_ERROR, NO_CONTENT, OK}
import play.api.libs.json.Json
import play.api.test.FakeRequest
import uk.gov.hmrc.http.HeaderCarrier
import example.utils.TestUtils

import scala.concurrent.{ExecutionContext, Future}

class GetCISDeductionsControllerSpec extends TestUtils {

  val service: CISDeductionsService = mock[CISDeductionsService]
  val controller = new GetCISDeductionsController(service,authorisedAction, mockControllerComponents)

  val nino :String = "123456789"
  val mtdItID :String = "1234567890"
  val taxYear: Int = 2022

  private val fakeGetRequest = FakeRequest("GET", "/").withHeaders("MTDITID" -> mtdItID)

  def mockGetCISDeductions(data: AllCISDeductions):
  CallHandler4[String, Int, HeaderCarrier, ExecutionContext, Future[Either[DesErrorModel, AllCISDeductions]]] = {
    (service.getCISDeductions(_: String, _: Int)(_: HeaderCarrier, _: ExecutionContext))
      .expects(*, *, *, *)
      .returning(Future.successful(Right(data)))
  }

  def mockGetCISDeductionsError(): CallHandler4[String, Int, HeaderCarrier, ExecutionContext, Future[Either[DesErrorModel, AllCISDeductions]]] = {
    (service.getCISDeductions(_: String, _: Int)(_: HeaderCarrier, _: ExecutionContext))
      .expects(*, *, *, *)
      .returning(Future.successful(Left(DesErrorModel(
        INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError
      ))))
  }

  "calling .getCISDeductions" should {
    "with existing customer and contractor data" should {
      "return an OK 200 response when called as an individual" in {
        val result = {
          mockAuth()
          mockGetCISDeductions(AllCISDeductions(
            customerCISDeductions = Some(customerCISSource(taxYear)),
            contractorCISDeductions = Some(contractorCISSource(taxYear))
          ))
          controller.getCISDeductions(nino, taxYear)(fakeGetRequest)
        }
        status(result) mustBe OK
        Json.parse(bodyOf(result)) mustBe Json.toJson(
          AllCISDeductions(
            customerCISDeductions = Some(customerCISSource(taxYear)),
            contractorCISDeductions = Some(contractorCISSource(taxYear))
          )
        )
      }
    }

    "without existing customer and contractor data" should {
      "return an NO CONTENT 204 response when called as an individual" in {
        val result = {
          mockAuth()
          mockGetCISDeductions(AllCISDeductions(
            customerCISDeductions = None,
            contractorCISDeductions = None
          ))
          controller.getCISDeductions(nino, taxYear)(fakeGetRequest)
        }
        status(result) mustBe NO_CONTENT
      }
    }

    "when an error is returned" should {
      "return the error response when called as an individual" in {
        val result = {
          mockAuth()
          mockGetCISDeductionsError()
          controller.getCISDeductions(nino, taxYear)(fakeGetRequest)
        }
        status(result) mustBe INTERNAL_SERVER_ERROR
        bodyOf(result) mustBe """{"code":"PARSING_ERROR","reason":"Error parsing response from DES"}"""
      }
    }
  }
}
