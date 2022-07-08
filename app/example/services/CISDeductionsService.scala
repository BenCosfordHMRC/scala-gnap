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

import example.common.CISSource.{CONTRACTOR, CUSTOMER}
import example.connectors.CISDeductionsConnector
import example.models.get.{AllCISDeductions, CISSource}
import example.models.{CreateCISDeductions, DesErrorModel, UpdateCISDeductions}
import example.models.submission.CISSubmission
import uk.gov.hmrc.http.HeaderCarrier

import javax.inject.Inject
import scala.concurrent.{ExecutionContext, Future}

class CISDeductionsService @Inject()(cisDeductionsConnector: CISDeductionsConnector) {

  def submitCISDeductions(nino: String, taxYear: Int, cisSubmission: CISSubmission)
                         (implicit hc: HeaderCarrier, ec: ExecutionContext): Future[Either[DesErrorModel, Option[String]]] = {
    (cisSubmission: @unchecked) match {
      case CISSubmission(Some(employerRef), Some(contractorName), periodData, None) =>
        cisDeductionsConnector.create(nino, taxYear, CreateCISDeductions(employerRef, contractorName, periodData)).map(response =>
          response.right.map(success => Some(success.submissionId)))
      case CISSubmission(None, None, periodData, Some(submissionId)) =>
        cisDeductionsConnector.update(nino, submissionId, UpdateCISDeductions(periodData = periodData)).map(response => response.right.map(_ => None))
    }
  }

  def getCISDeductions(nino: String, taxYear: Int)
                      (implicit hc: HeaderCarrier, ec: ExecutionContext): Future[Either[DesErrorModel, AllCISDeductions]] = {

    getContractorCISDeductions(nino, taxYear).flatMap {
      case Left(error) => Future.successful(Left(error))
      case Right(contractorCISDeductions) => getCustomerCISDeductions(nino, taxYear).map {
        case Left(error) => Left(error)
        case Right(customerCISDeductions) => Right(
          AllCISDeductions(
            customerCISDeductions = customerCISDeductions,
            contractorCISDeductions = contractorCISDeductions
          )
        )
      }
    }
  }

  def deleteCISDeductionsSubmission(nino: String, submissionId: String)(implicit hc: HeaderCarrier): Future[Either[DesErrorModel, Unit]] = {
    cisDeductionsConnector.delete(nino,submissionId)
  }

  private def getCustomerCISDeductions(nino: String, taxYear: Int)(implicit hc: HeaderCarrier): Future[Either[DesErrorModel, Option[CISSource]]] = {
    cisDeductionsConnector.get(nino, taxYear, CUSTOMER)
  }

  private def getContractorCISDeductions(nino: String, taxYear: Int)(implicit hc: HeaderCarrier): Future[Either[DesErrorModel, Option[CISSource]]] = {
    cisDeductionsConnector.get(nino, taxYear, CONTRACTOR)
  }
}
