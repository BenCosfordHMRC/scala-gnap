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

package controllers

import models.{DesErrorBodyModel, DesErrorModel}
import play.api.http.Status.{INTERNAL_SERVER_ERROR, NO_CONTENT}
import play.api.mvc.AnyContentAsEmpty
import play.api.test.FakeRequest
import support.mocks.MockCISDeductionsService
import utils.TestUtils

class DeleteCISDeductionsSubmissionControllerSpec extends TestUtils with MockCISDeductionsService {

  private val controller = new DeleteCISDeductionsSubmissionController(mockCISDeductionsService, authorisedAction, mockControllerComponents)

  private val nino: String = "123456789"
  private val mtdItID: String = "1234567890"
  private val taxYear: Int = 2022

  override val fakeRequest: FakeRequest[AnyContentAsEmpty.type] = FakeRequest("DELETE", "/").withHeaders("MTDITID" -> mtdItID)

  "calling .deleteCISDeductionsSubmission" should {
    "return an NO CONTENT response when successfully deletes the data" in {
      val result = {
        mockAuth()
        mockDeleteCISDeductionsSubmission(
          nino, "submissionId", Right(())
        )
        controller.deleteCISDeductionsSubmission(nino, taxYear, "submissionId")(fakeRequest)
      }
      status(result) mustBe NO_CONTENT
    }

    "when an error is returned" should {
      "return the error response" in {
        val result = {
          mockAuth()
          mockDeleteCISDeductionsSubmission(
            nino, "submissionId", Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError))
          )
          controller.deleteCISDeductionsSubmission(nino, taxYear, "submissionId")(fakeRequest)
        }
        status(result) mustBe INTERNAL_SERVER_ERROR
        bodyOf(result) mustBe """{"code":"PARSING_ERROR","reason":"Error parsing response from DES"}"""
      }
    }
  }
}
