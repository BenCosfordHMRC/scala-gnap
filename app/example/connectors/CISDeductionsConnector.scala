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
import example.connectors.httpParsers.CreateCISDeductionsParser.{CreateCISDeductionsResponse, CreateCISDeductionsResponseHttpReads}
import example.connectors.httpParsers.DeleteCISDeductionsHttpParser.{DeleteCISDeductionsHttpReads, DeleteCISDeductionsResponse}
import example.connectors.httpParsers.GetCISDeductionsHttpParser.{GetCISDeductionsResponse, GetCISDeductionsResponseHttpReads}
import example.connectors.httpParsers.UpdateCISDeductionsHttpParser.{UpdateCISDeductionsResponse, UpdateCISDeductionsResponseHttpReads}
import example.models.{CreateCISDeductions, CreateCISDeductionsApi, UpdateCISDeductions}
import example.utils.CISTaxYearHelper

import javax.inject.Inject
import example.models.{CreateCISDeductions, CreateCISDeductionsApi, UpdateCISDeductions}
import uk.gov.hmrc.http.{HeaderCarrier, HttpClient}

import scala.concurrent.{ExecutionContext, Future}

class CISDeductionsConnector @Inject()(val http: HttpClient,
                                       val appConfig: AppConfig)(implicit ec: ExecutionContext) extends DesConnector {

  def update(nino: String, submissionId: String, model: UpdateCISDeductions)
            (implicit hc: HeaderCarrier): Future[UpdateCISDeductionsResponse] = {

    val updateUri: String = baseUrl + s"/income-tax/cis/deductions/$nino/submissionId/$submissionId"

    def desCall(implicit hc: HeaderCarrier): Future[UpdateCISDeductionsResponse] = {
      http.PUT[UpdateCISDeductions, UpdateCISDeductionsResponse](
        updateUri, model)(UpdateCISDeductions.format.writes, UpdateCISDeductionsResponseHttpReads, hc, ec)
    }

    desCall(desHeaderCarrier(updateUri))
  }

  def get(nino: String, taxYear: Int, source: String)(implicit hc: HeaderCarrier): Future[GetCISDeductionsResponse] = {

    val cisTaxYear = CISTaxYearHelper.cisTaxYearConverter(taxYear)

    val getUri: String = baseUrl + s"/income-tax/cis/deductions/$nino?periodStart=${cisTaxYear.fromDate}&periodEnd=${cisTaxYear.toDate}&source=$source"

    def desCall(implicit hc: HeaderCarrier): Future[GetCISDeductionsResponse] = {
      http.GET[GetCISDeductionsResponse](getUri)(GetCISDeductionsResponseHttpReads, hc, ec)
    }

    desCall(desHeaderCarrier(getUri))
  }

  def delete(nino: String, submissionId: String)(implicit hc: HeaderCarrier): Future[DeleteCISDeductionsResponse] = {

    val deleteCISDeductionsUri: String = baseUrl + s"/income-tax/cis/deductions/$nino/submissionId/$submissionId"

    def desCall(implicit hc: HeaderCarrier): Future[DeleteCISDeductionsResponse] = {
      http.DELETE[DeleteCISDeductionsResponse](deleteCISDeductionsUri)(DeleteCISDeductionsHttpReads, hc, ec)
    }

    desCall(desHeaderCarrier(deleteCISDeductionsUri))
  }

  def create(nino: String, taxYear: Int, model: CreateCISDeductions)
            (implicit hc: HeaderCarrier): Future[CreateCISDeductionsResponse] = {
    val createCISDeductionsUri = baseUrl + s"/income-tax/cis/deductions/$nino"

    def desCall(implicit hc: HeaderCarrier): Future[CreateCISDeductionsResponse] = {
      http.POST[CreateCISDeductionsApi, CreateCISDeductionsResponse](
        createCISDeductionsUri, model.toApiModel(taxYear))(CreateCISDeductionsApi.format.writes, CreateCISDeductionsResponseHttpReads, hc,ec)
    }

    desCall(desHeaderCarrier(createCISDeductionsUri))
  }

}
