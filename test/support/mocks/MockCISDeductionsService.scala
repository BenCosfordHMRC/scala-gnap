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

package support.mocks

import example.models.DesErrorModel
import example.models.submission.CISSubmission
import example.services.CISDeductionsService
import org.scalamock.handlers.{CallHandler3, CallHandler5}
import org.scalamock.scalatest.MockFactory
import uk.gov.hmrc.http.HeaderCarrier

import scala.concurrent.{ExecutionContext, Future}

trait MockCISDeductionsService extends MockFactory {

  protected val mockCISDeductionsService: CISDeductionsService = mock[CISDeductionsService]

  def mockDeleteCISDeductionsSubmission(nino: String,
                                        submissionId: String,
                                        response: Either[DesErrorModel, Unit]): CallHandler3[String,
    String, HeaderCarrier, Future[Either[DesErrorModel, Unit]]] = {
    (mockCISDeductionsService.deleteCISDeductionsSubmission(_: String, _: String)(_: HeaderCarrier))
      .expects(nino, submissionId, *)
      .returning(Future.successful(response))
  }

  def mockSubmitCISDeductions(nino: String,
                              taxYear: Int,
                              data: CISSubmission,
                              response: Either[DesErrorModel, Option[String]]): CallHandler5[String, Int, CISSubmission, HeaderCarrier,
    ExecutionContext, Future[Either[DesErrorModel, Option[String]]]] = {
    (mockCISDeductionsService.submitCISDeductions(_: String, _: Int, _: CISSubmission)(_: HeaderCarrier, _: ExecutionContext))
      .expects(nino, taxYear, data, *, *)
      .returning(Future.successful(response))
  }
}
