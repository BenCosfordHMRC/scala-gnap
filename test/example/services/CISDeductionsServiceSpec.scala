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

package example.services

import builders.CISSourceBuilder.{contractorCISSource, customerCISSource}
import builders.CISSubmissionBuilder.{aCreateCISSubmission, anUpdateCISSubmission}
import example.models.get.AllCISDeductions
import example.common.CISSource.{CONTRACTOR, CUSTOMER}
import example.models.{CreateCISDeductions, CreateCISDeductionsSuccess, DesErrorBodyModel, DesErrorModel, UpdateCISDeductions}
import example.services.CISDeductionsService
import models._
import play.api.http.Status.INTERNAL_SERVER_ERROR
import support.mocks.MockCISDeductionsConnector
import example.utils.TestUtils

class CISDeductionsServiceSpec extends TestUtils with MockCISDeductionsConnector{

  private val underTest = new CISDeductionsService(
    mockCISDeductionsConnector
  )

  private val nino = "AA66666B"
  private val taxYear = 2022

  "submitCISDeductions" should {
    "return an error from the create contractor call" in {

      mockCreate(nino, taxYear, CreateCISDeductions(
        aCreateCISSubmission.employerRef.get,aCreateCISSubmission.contractorName.get,aCreateCISSubmission.periodData
      ), Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError)))

      val result = underTest.submitCISDeductions(nino, taxYear, aCreateCISSubmission)

      await(result) mustBe Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError))
    }
    "return an id from the create contractor call" in {

      mockCreate(nino, taxYear, CreateCISDeductions(
        aCreateCISSubmission.employerRef.get,aCreateCISSubmission.contractorName.get,aCreateCISSubmission.periodData
      ), Right(CreateCISDeductionsSuccess("id")))

      val result = underTest.submitCISDeductions(nino, taxYear, aCreateCISSubmission)

      await(result) mustBe Right(Some("id"))
    }
    "return None from the update contractor call" in {

      mockUpdate(nino, anUpdateCISSubmission.submissionId.get, UpdateCISDeductions(anUpdateCISSubmission.periodData), Right(()))

      val result = underTest.submitCISDeductions(nino, taxYear, anUpdateCISSubmission)

      await(result) mustBe Right(None)
    }
    "return an error from the update contractor call" in {

      mockUpdate(nino, anUpdateCISSubmission.submissionId.get, UpdateCISDeductions(anUpdateCISSubmission.periodData),
        Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError)))

      val result = underTest.submitCISDeductions(nino, taxYear, anUpdateCISSubmission)

      await(result) mustBe Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError))
    }
  }

  "getCISDeductions" should {
    "return an error from the first contractor call" in {

      mockGet(nino, taxYear, CONTRACTOR, Left(DesErrorModel(
        INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError
      )))

      await(underTest.getCISDeductions(nino, taxYear)) mustBe Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError))
    }

    "return an error from the second customer call" in {

      mockGet(nino, taxYear, CUSTOMER, Left(DesErrorModel(
        INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError
      )))
      mockGet(nino, taxYear, CONTRACTOR, Right(Some(contractorCISSource(taxYear))))

      await(underTest.getCISDeductions(nino, taxYear)) mustBe Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError))
    }

    "return both customer and contractor data" in {

      mockGet(nino, taxYear, CUSTOMER, Right(Some(customerCISSource(taxYear))))
      mockGet(nino, taxYear, CONTRACTOR, Right(Some(contractorCISSource(taxYear))))

      await(underTest.getCISDeductions(nino, taxYear)) mustBe Right(AllCISDeductions(Some(customerCISSource(taxYear)), Some(contractorCISSource(taxYear))))
    }

    "return no data for customer and contractor" in {

      mockGet(nino, taxYear, CUSTOMER, Right(None))
      mockGet(nino, taxYear, CONTRACTOR, Right(None))

      await(underTest.getCISDeductions(nino, taxYear)) mustBe Right(AllCISDeductions(None, None))
    }

    "return customer data" in {

      mockGet(nino, taxYear, CUSTOMER, Right(Some(customerCISSource(taxYear))))
      mockGet(nino, taxYear, CONTRACTOR, Right(None))

      await(underTest.getCISDeductions(nino, taxYear)) mustBe Right(AllCISDeductions(Some(customerCISSource(taxYear)), None))
    }

    "return contractor data" in {

      mockGet(nino, taxYear, CUSTOMER, Right(None))
      mockGet(nino, taxYear, CONTRACTOR, Right(Some(contractorCISSource(taxYear))))

      await(underTest.getCISDeductions(nino, taxYear)) mustBe Right(AllCISDeductions(None, Some(contractorCISSource(taxYear))))
    }
  }

  ".deleteCISDeductionsSubmission" should {
    "return no content when deleted" in {

      mockDelete(nino, "submissionId", Right(()))

      val result = underTest.deleteCISDeductionsSubmission(nino, "submissionId")

      await(result) mustBe Right(())
    }
    "return error when failed to delete" in {

      mockDelete(nino, "submissionId",  Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError)))

      val result = underTest.deleteCISDeductionsSubmission(nino, "submissionId")

      await(result) mustBe Left(DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError))
    }
  }
}
