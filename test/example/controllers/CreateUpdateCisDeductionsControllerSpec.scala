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

import builders.CISSubmissionBuilder.{aCreateCISSubmission, aPeriodData, anUpdateCISSubmission}
import example.controllers.CreateUpdateCisDeductionsController
import example.models.{CreateCISDeductionsSuccess, DesErrorBodyModel, DesErrorModel}
import play.api.http.Status.{BAD_REQUEST, INTERNAL_SERVER_ERROR, OK}
import play.api.libs.json.{JsValue, Json}
import play.api.mvc.AnyContentAsJson
import play.api.test.FakeRequest
import support.mocks.MockCISDeductionsService
import example.utils.TestUtils

class CreateUpdateCisDeductionsControllerSpec extends TestUtils with MockCISDeductionsService {

  private val controller = new CreateUpdateCisDeductionsController(mockCISDeductionsService,authorisedAction, mockControllerComponents)

  private val nino :String = "123456789"
  private val mtdItID :String = "1234567890"
  private val taxYear: Int = 2022

  private def fakeRequest(body: JsValue): FakeRequest[AnyContentAsJson] = FakeRequest("POST", "/").withHeaders("MTDITID" -> mtdItID).withJsonBody(body)

  "calling .postCISDeductions" should {
    "with create body" should {
      "return an OK 200 response" in {
        val result = {
          mockAuth()
          mockSubmitCISDeductions(nino, taxYear, aCreateCISSubmission, Right(Some("id")))
          controller.postCISDeductions(nino, taxYear)(fakeRequest(Json.toJson(aCreateCISSubmission)))
        }
        status(result) mustBe OK
        Json.parse(bodyOf(result)) mustBe Json.toJson(CreateCISDeductionsSuccess("id"))
      }
    }

    "with update body" should {
      "return an OK 200 response" in {
        val result = {
          mockAuth()
          mockSubmitCISDeductions(nino, taxYear, anUpdateCISSubmission, Right(None))
          controller.postCISDeductions(nino, taxYear)(fakeRequest(Json.toJson(anUpdateCISSubmission)))
        }
        status(result) mustBe OK
      }
      "return an OK 200 response when more than one period" in {
        val result = {
          mockAuth()
          mockSubmitCISDeductions(nino, taxYear, anUpdateCISSubmission.copy(periodData = Seq(aPeriodData, aPeriodData)), Right(None))
          controller.postCISDeductions(nino, taxYear)(fakeRequest(Json.toJson(anUpdateCISSubmission.copy(periodData = Seq(aPeriodData, aPeriodData)))))
        }
        status(result) mustBe OK
      }
    }

    "return a bad request" when {
      "a submission id is passed alongside a name and reference" in {
        val body: JsValue = {
          Json.parse("""{
            |	"employerRef": "123/AB123456",
            |	"contractorName": "ABC Steelworks",
            |	"periodData": [{
            |		"deductionFromDate": "2021-04-06",
            |		"deductionToDate": "2021-05-05",
            |		"grossAmountPaid": 1,
            |		"deductionAmount": 1,
            |		"costOfMaterials": 1
            |	}],
            | "submissionId": "1234567890"
            |}""".stripMargin)
        }

        val result = {
          mockAuth()
          controller.postCISDeductions(nino, taxYear)(fakeRequest(body))
        }
        status(result) mustBe BAD_REQUEST
      }
      "period data is empty" in {
        val body: JsValue = {
          Json.parse("""{
            |	"employerRef": "123/AB123456",
            |	"contractorName": "ABC Steelworks",
            |	"periodData": []
            |}""".stripMargin)
        }

        val result = {
          mockAuth()
          controller.postCISDeductions(nino, taxYear)(fakeRequest(body))
        }
        status(result) mustBe BAD_REQUEST
      }
      "period data is none" in {
        val body: JsValue = {
          Json.parse("""{
            |	"employerRef": "123/AB123456",
            |	"contractorName": "ABC Steelworks"
            |}""".stripMargin)
        }

        val result = {
          mockAuth()
          controller.postCISDeductions(nino, taxYear)(fakeRequest(body))
        }
        status(result) mustBe BAD_REQUEST
      }
      "submission id is empty alongside no name" in {
        val body: JsValue = {
          Json.parse("""{
            |	"employerRef": "123/AB123456",
            |	"periodData": [{
            |		"deductionFromDate": "2021-04-06",
            |		"deductionToDate": "2021-05-05",
            |		"grossAmountPaid": 1,
            |		"deductionAmount": 1,
            |		"costOfMaterials": 1
            |	}]
            |}""".stripMargin)
        }

        val result = {
          mockAuth()
          controller.postCISDeductions(nino, taxYear)(fakeRequest(body))
        }
        status(result) mustBe BAD_REQUEST
      }
      "submission id is empty alongside no name and no reference" in {
        val body: JsValue = {
          Json.parse("""{
            |	"periodData": [{
            |		"deductionFromDate": "2021-04-06",
            |		"deductionToDate": "2021-05-05",
            |		"grossAmountPaid": 1,
            |		"deductionAmount": 1,
            |		"costOfMaterials": 1
            |	}]
            |}""".stripMargin)
        }

        val result = {
          mockAuth()
          controller.postCISDeductions(nino, taxYear)(fakeRequest(body))
        }
        status(result) mustBe BAD_REQUEST
      }
    }

    "when an error is returned" should {
      "return the error response when called as an individual" in {
        val result = {
          mockAuth()
          mockSubmitCISDeductions(nino, taxYear, aCreateCISSubmission, Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError)))
          controller.postCISDeductions(nino, taxYear)(fakeRequest(Json.toJson(aCreateCISSubmission)))
        }
        status(result) mustBe INTERNAL_SERVER_ERROR
        bodyOf(result) mustBe """{"code":"PARSING_ERROR","reason":"Error parsing response from DES"}"""
      }
    }
  }
}
