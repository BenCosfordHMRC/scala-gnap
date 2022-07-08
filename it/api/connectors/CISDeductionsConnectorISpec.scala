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

package api.connectors

import builders.CISSourceBuilder.{contractorCISSource, customerCISSource}
import com.github.tomakehurst.wiremock.http.HttpHeader
import example.config.MockAppConfig
import example.connectors.CISDeductionsConnector
import example.models.{CreateCISDeductions, CreateCISDeductionsApi, CreateCISDeductionsSuccess, DesErrorBodyModel, DesErrorModel, PeriodData, UpdateCISDeductions}
import example.models.get.{CISDeductions, CISSource, GetPeriodData}
import models._
import play.api.http.Status._
import play.api.libs.json.Json
import uk.gov.hmrc.http.{HeaderCarrier, HeaderNames, SessionId}
import utils.ConnectorIntegrationTest

import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.Duration

class CISDeductionsConnectorISpec extends ConnectorIntegrationTest {

  def connector(desHost: String = "localhost"): CISDeductionsConnector = new CISDeductionsConnector(httpClient, new MockAppConfig().config(desHost))

  val taxYear = 2022
  val nino: String = "AA123123A"
  val submissionId: String = "a111111a-abcd-111a-123a-11a1a111a1"

  implicit val hc: HeaderCarrier = HeaderCarrier(sessionId = Some(SessionId("sessionIdValue")))
  val updateCISDeductionsUrl: String = s"/income-tax/cis/deductions/$nino/submissionId/$submissionId"
  val deleteCISDeductionsUrl: String = s"/income-tax/cis/deductions/$nino/submissionId/$submissionId"
  val createCISDeductionsUrl: String = s"/income-tax/cis/deductions/$nino"

  val connectorWithInternalHost: CISDeductionsConnector = connector()
  val connectorWithExternalHost:  CISDeductionsConnector = connector("127.0.0.1")

  val updateCISDeductionsModel: UpdateCISDeductions =
    UpdateCISDeductions(
      Seq(PeriodData(
        deductionFromDate = "2019-04-06",
        deductionToDate = "2019-05-05",
        grossAmountPaid = Some(129.99),
        deductionAmount = 251.11,
        costOfMaterials = Some(30.00)
      ))
    )

  val createCISDeductionsModel: CreateCISDeductions = {
    CreateCISDeductions(
      "employerRef",
      "contractorName",
      Seq(PeriodData(
        deductionFromDate = "2019-04-06",
        deductionToDate = "2019-05-05",
        grossAmountPaid = Some(129.99),
        deductionAmount = 251.11,
        costOfMaterials = Some(30.00)
      ))
    )
  }

  val createCISDeductionsApiModel: CreateCISDeductionsApi = createCISDeductionsModel.toApiModel(taxYear)

  val createResponse: CreateCISDeductionsSuccess = CreateCISDeductionsSuccess("12345678")

  val headersSentToDes = Seq(
    new HttpHeader(HeaderNames.authorisation, "Bearer authorisation-token"),
    new HttpHeader(HeaderNames.xSessionId, "sessionIdValue")
  )

  ".update" should {

    "include internal headers" when {

      "the host for DES is 'Internal'" in {

        stubPutWithoutResponseBody(
          updateCISDeductionsUrl, Json.toJson(updateCISDeductionsModel).toString(), NO_CONTENT, headersSentToDes
        )

        Await.result(connectorWithInternalHost.update(nino, submissionId, updateCISDeductionsModel), Duration.Inf) shouldBe Right(())
      }

      "the host for DES is 'External'" in {
        stubPutWithoutResponseBody(
          updateCISDeductionsUrl, Json.toJson(updateCISDeductionsModel).toString(), NO_CONTENT)

        Await.result(connectorWithExternalHost.update(nino, submissionId, updateCISDeductionsModel), Duration.Inf) shouldBe Right(())
      }
    }

    "handle error" when {
      val desErrorBodyModel = DesErrorBodyModel("DES_CODE", "DES_REASON")

      Seq(BAD_REQUEST, UNPROCESSABLE_ENTITY, NOT_FOUND, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE).foreach { status =>
        s"DES returns $status" in {
          val desError = DesErrorModel(status, desErrorBodyModel)

          stubPutWithResponseBody(updateCISDeductionsUrl, Json.toJson(updateCISDeductionsModel).toString(), desError.toJson.toString(), status)
          Await.result(connectorWithInternalHost.update(nino, submissionId, updateCISDeductionsModel), Duration.Inf) shouldBe Left(desError)
        }
      }
      s"DES returns unexpected error code - BAD_GATEWAY (502)" in {
        val desError = DesErrorModel(INTERNAL_SERVER_ERROR, desErrorBodyModel)

        stubPutWithResponseBody(updateCISDeductionsUrl, Json.toJson(updateCISDeductionsModel).toString(), desError.toJson.toString(), BAD_GATEWAY)

        Await.result(connectorWithInternalHost.update(nino, submissionId, updateCISDeductionsModel), Duration.Inf) shouldBe Left(desError)
      }
    }
  }

  //scalastyle:off
  def getUrl(taxYear: Int, source: String): String = s"/income-tax/cis/deductions/$nino\\?periodStart=${taxYear-1}-04-06&periodEnd=$taxYear-04-05&source=$source"

  def smallContractorResult(taxYear: Int): CISSource = CISSource(
    Some(100),None,None,Seq(
      CISDeductions(
        s"${taxYear-1}-04-06",
        s"$taxYear-04-05",
        None,
        "111/11111",
        Some(100.00),
        None,
        None,
        Seq(
          GetPeriodData(
            s"${taxYear-1}-04-06",
            s"${taxYear-1}-05-05",
            Some(100.00),
            None,
            None,
            "2022-05-11T16:38:57.489Z",
            None,
            "contractor"
          )
        )
      )
    )
  )

  def customerResponse(taxYear:Int): String =
    s"""{
       |	"totalDeductionAmount": 400.00,
       |	"totalCostOfMaterials": 400.00,
       |	"totalGrossAmountPaid": 400.00,
       |	"cisDeductions": [{
       |		"fromDate": "${taxYear-1}-04-06",
       |		"toDate": "$taxYear-04-05",
       |		"contractorName": "Contractor 1",
       |		"employerRef": "111/11111",
       |		"totalDeductionAmount": 200.00,
       |		"totalCostOfMaterials": 200.00,
       |		"totalGrossAmountPaid": 200.00,
       |		"periodData": [{
       |			"deductionFromDate": "${taxYear-1}-04-06",
       |			"deductionToDate": "${taxYear-1}-05-05",
       |			"deductionAmount": 100.00,
       |			"costOfMaterials": 100.00,
       |			"grossAmountPaid": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"submissionId": "4557ecb5-fd32-48cc-81f5-e6acd1099f3c",
       |			"source": "customer"
       |		},{
       |			"deductionFromDate": "${taxYear-1}-05-06",
       |			"deductionToDate": "${taxYear-1}-06-05",
       |			"deductionAmount": 100.00,
       |			"costOfMaterials": 100.00,
       |			"grossAmountPaid": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"submissionId": "4557ecb5-fd32-48cc-81f5-e6acd1099f3c",
       |			"source": "customer"
       |		}]
       |	},{
       |		"fromDate": "${taxYear - 1}-04-06",
       |		"toDate": "$taxYear-04-05",
       |		"contractorName": "Contractor 2",
       |		"employerRef": "222/11111",
       |		"totalDeductionAmount": 200.00,
       |		"totalCostOfMaterials": 200.00,
       |		"totalGrossAmountPaid": 200.00,
       |		"periodData": [{
       |			"deductionFromDate": "${taxYear-1}-04-06",
       |			"deductionToDate": "${taxYear-1}-05-05",
       |			"deductionAmount": 100.00,
       |			"costOfMaterials": 100.00,
       |			"grossAmountPaid": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"submissionId": "4557ecb5-fd32-48cc-81f5-e6acd1099f3c",
       |			"source": "customer"
       |		},{
       |			"deductionFromDate": "${taxYear-1}-05-06",
       |			"deductionToDate": "${taxYear-1}-06-05",
       |			"deductionAmount": 100.00,
       |			"costOfMaterials": 100.00,
       |			"grossAmountPaid": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"submissionId": "4557ecb5-fd32-48cc-81f5-e6acd1099f3c",
       |			"source": "customer"
       |		}]
       |	}]
       |}""".stripMargin

  def contractorResponse(taxYear:Int): String =
    s"""{
       |	"totalDeductionAmount": 400.00,
       |	"totalCostOfMaterials": 400.00,
       |	"totalGrossAmountPaid": 400.00,
       |	"cisDeductions": [{
       |		"fromDate": "${taxYear-1}-04-06",
       |		"toDate": "$taxYear-04-05",
       |		"contractorName": "Contractor 1",
       |		"employerRef": "111/11111",
       |		"totalDeductionAmount": 200.00,
       |		"totalCostOfMaterials": 200.00,
       |		"totalGrossAmountPaid": 200.00,
       |		"periodData": [{
       |			"deductionFromDate": "${taxYear-1}-04-06",
       |			"deductionToDate": "${taxYear-1}-05-05",
       |			"deductionAmount": 100.00,
       |			"costOfMaterials": 100.00,
       |			"grossAmountPaid": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"source": "contractor"
       |		},{
       |			"deductionFromDate": "${taxYear-1}-05-06",
       |			"deductionToDate": "${taxYear-1}-06-05",
       |			"deductionAmount": 100.00,
       |			"costOfMaterials": 100.00,
       |			"grossAmountPaid": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"source": "contractor"
       |		}]
       |	},{
       |		"fromDate": "${taxYear - 1}-04-06",
       |		"toDate": "$taxYear-04-05",
       |		"contractorName": "Contractor 2",
       |		"employerRef": "222/11111",
       |		"totalDeductionAmount": 200.00,
       |		"totalCostOfMaterials": 200.00,
       |		"totalGrossAmountPaid": 200.00,
       |		"periodData": [{
       |			"deductionFromDate": "${taxYear-1}-04-06",
       |			"deductionToDate": "${taxYear-1}-05-05",
       |			"deductionAmount": 100.00,
       |			"costOfMaterials": 100.00,
       |			"grossAmountPaid": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"source": "contractor"
       |		},{
       |			"deductionFromDate": "${taxYear-1}-05-06",
       |			"deductionToDate": "${taxYear-1}-06-05",
       |			"deductionAmount": 100.00,
       |			"costOfMaterials": 100.00,
       |			"grossAmountPaid": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"source": "contractor"
       |		}]
       |	}]
       |}""".stripMargin

  def smallContractorResponse(taxYear:Int): String =
    s"""{
       |	"totalDeductionAmount": 100.00,
       |	"cisDeductions": [{
       |		"fromDate": "${taxYear-1}-04-06",
       |		"toDate": "$taxYear-04-05",
       |		"employerRef": "111/11111",
       |		"totalDeductionAmount": 100.00,
       |		"periodData": [{
       |			"deductionFromDate": "${taxYear-1}-04-06",
       |			"deductionToDate": "${taxYear-1}-05-05",
       |			"deductionAmount": 100.00,
       |			"submissionDate": "2022-05-11T16:38:57.489Z",
       |			"source": "contractor"
       |		}]
       |	}]
       |}""".stripMargin

  def emptySeqResponse: String =
    s"""{
       |	"cisDeductions": []
       |}""".stripMargin

  "get" should {
    "include internal headers" when {
      "the host for DES is 'Internal' and is retrieving customer data" in {

        stubGetWithResponseBody(getUrl(taxYear, "customer"), OK, customerResponse(taxYear), headersSentToDes)

        Await.result(connectorWithInternalHost.get(nino, taxYear, "customer"), Duration.Inf) shouldBe Right(
          Some(
            customerCISSource(taxYear)
          )
        )
      }

      "the host for DES is 'External' and is retrieving customer data" in {

        stubGetWithResponseBody(getUrl(taxYear, "customer"), OK, customerResponse(taxYear))

        Await.result(connectorWithExternalHost.get(nino, taxYear, "customer"), Duration.Inf) shouldBe Right(
          Some(
            customerCISSource(taxYear)
          )
        )
      }
    }

    "return contractor data without submission ids" in {
      stubGetWithResponseBody(getUrl(taxYear - 1, "contractor"), OK, contractorResponse(taxYear - 1))

      Await.result(connectorWithExternalHost.get(nino, taxYear - 1, "contractor"), Duration.Inf) shouldBe Right(
        Some(
          contractorCISSource(taxYear - 1)
        )
      )
    }

    "return smallest model" in {
      stubGetWithResponseBody(getUrl(taxYear - 1, "contractor"), OK, smallContractorResponse(taxYear - 1))

      Await.result(connectorWithExternalHost.get(nino, taxYear - 1, "contractor"), Duration.Inf) shouldBe Right(
        Some(
          smallContractorResult(taxYear - 1)
        )
      )
    }

    "return a right none if empty seq of cis deductions" in {
      stubGetWithResponseBody(getUrl(taxYear, "customer"), OK, emptySeqResponse)

      Await.result(connectorWithExternalHost.get(nino, taxYear, "customer"), Duration.Inf) shouldBe Right(
        None
      )
    }

    "return a right none if not found" in {
      stubGetWithResponseBody(getUrl(taxYear, "customer"), NOT_FOUND, "{}")

      Await.result(connectorWithExternalHost.get(nino, taxYear, "customer"), Duration.Inf) shouldBe Right(
        None
      )
    }

    "handle malformed json" in {
      stubGetWithResponseBody(getUrl(taxYear, "customer"), OK, s"""{"cisDeductions": {}}""".stripMargin)

      val desError = DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError)
      Await.result(connectorWithExternalHost.get(nino, taxYear, "customer"), Duration.Inf) shouldBe Left(
        desError
      )
    }

    "handle error" when {
      val desErrorBodyModel = DesErrorBodyModel("DES_CODE", "DES_REASON")

      Seq(BAD_REQUEST, UNPROCESSABLE_ENTITY, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE).foreach { status =>
        s"DES returns $status" in {
          val desError = DesErrorModel(status, desErrorBodyModel)

          stubGetWithResponseBody(getUrl(taxYear, "customer"), status, desError.toJson.toString())
          Await.result(connectorWithInternalHost.get(nino, taxYear, "customer"), Duration.Inf) shouldBe Left(desError)
        }
      }
      s"DES returns unexpected error code - BAD_GATEWAY (502)" in {
        val desError = DesErrorModel(INTERNAL_SERVER_ERROR, desErrorBodyModel)

        stubGetWithResponseBody(getUrl(taxYear, "customer"), BAD_GATEWAY, desError.toJson.toString())
        Await.result(connectorWithInternalHost.get(nino, taxYear, "customer"), Duration.Inf) shouldBe Left(desError)
      }
    }
  }

  ".delete" should {

    "include internal headers" when {

      "the host for DES is 'Internal'" in {

        stubDeleteWithoutResponseBody(deleteCISDeductionsUrl, NO_CONTENT, headersSentToDes)

        Await.result(connectorWithInternalHost.delete(nino, submissionId), Duration.Inf) shouldBe Right(())
      }

      "the host for DES is 'External'" in {
        stubDeleteWithoutResponseBody(deleteCISDeductionsUrl, NO_CONTENT)

        Await.result(connectorWithExternalHost.delete(nino, submissionId), Duration.Inf) shouldBe Right(())
      }
    }

    "handle error" when {
      val desErrorBodyModel = DesErrorBodyModel("DES_CODE", "DES_REASON")

      Seq(BAD_REQUEST, NOT_FOUND, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE).foreach { status =>
        s"DES returns $status" in {
          val desError = DesErrorModel(status, desErrorBodyModel)

          stubDeleteWithResponseBody(deleteCISDeductionsUrl, status, desError.toJson.toString())
          Await.result(connectorWithInternalHost.delete(nino, submissionId), Duration.Inf) shouldBe Left(desError)
        }
      }
      s"DES returns unexpected error code - FORBIDDEN (403)" in {
        val desError = DesErrorModel(INTERNAL_SERVER_ERROR, desErrorBodyModel)

        stubDeleteWithResponseBody(deleteCISDeductionsUrl, FORBIDDEN, desError.toJson.toString())

        Await.result(connectorWithInternalHost.delete(nino, submissionId), Duration.Inf) shouldBe Left(desError)
      }
    }
  }

  ".create" should {

    "include internal headers" when {

      "the host for DES is 'Internal'" in {

        stubPostWithResponseBody(
          createCISDeductionsUrl, OK, Json.toJson(createCISDeductionsApiModel).toString(), Json.toJson(createResponse).toString, headersSentToDes
        )

        Await.result(connectorWithInternalHost.create(nino, taxYear,createCISDeductionsModel), Duration.Inf) shouldBe Right(createResponse)
      }

      "the host for DES is 'External'" in {
        stubPostWithResponseBody(
          createCISDeductionsUrl, OK, Json.toJson(createCISDeductionsApiModel).toString(), Json.toJson(createResponse).toString, headersSentToDes
        )

        Await.result(connectorWithExternalHost.create(nino, taxYear, createCISDeductionsModel), Duration.Inf) shouldBe Right(createResponse)
      }
    }

    "handle error" when {
      val desErrorBodyModel = DesErrorBodyModel("DES_CODE", "DES_REASON")

      Seq(CONFLICT, BAD_REQUEST, UNPROCESSABLE_ENTITY, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE).foreach { status =>
        s"DES returns $status" in {
          val desError = DesErrorModel(status, desErrorBodyModel)

          stubPostWithResponseBody(createCISDeductionsUrl, status, Json.toJson(createCISDeductionsApiModel).toString(), desError.toJson.toString())
          Await.result(connectorWithInternalHost.create(nino, taxYear, createCISDeductionsModel), Duration.Inf) shouldBe Left(desError)
        }
      }
      s"DES returns unexpected error code - BAD_GATEWAY (502)" in {
        val desError = DesErrorModel(INTERNAL_SERVER_ERROR, desErrorBodyModel)

        stubPostWithResponseBody(createCISDeductionsUrl, BAD_GATEWAY, Json.toJson(createCISDeductionsApiModel).toString(), desError.toJson.toString())

        Await.result(connectorWithInternalHost.create(nino, taxYear, createCISDeductionsModel), Duration.Inf) shouldBe Left(desError)
      }
      s"DES returns OK with bad Json" in {
        val desError = DesErrorModel(INTERNAL_SERVER_ERROR, DesErrorBodyModel.parsingError)

        stubPostWithResponseBody(createCISDeductionsUrl, OK, Json.toJson(createCISDeductionsApiModel).toString(),
          Json.toJson(createCISDeductionsApiModel).toString(), headersSentToDes)

        Await.result(connectorWithInternalHost.create(nino, taxYear,createCISDeductionsModel), Duration.Inf) shouldBe Left(desError)
      }
    }
  }
}


