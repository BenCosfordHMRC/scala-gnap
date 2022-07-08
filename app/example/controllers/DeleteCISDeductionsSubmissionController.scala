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

import example.actions.AuthorisedAction
import example.services.CISDeductionsService
import play.api.Logging
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController

import javax.inject.Inject
import scala.concurrent.ExecutionContext

class DeleteCISDeductionsSubmissionController @Inject()(service: CISDeductionsService,
                                                        auth: AuthorisedAction,
                                                        cc: ControllerComponents)
                                                       (implicit ec: ExecutionContext) extends BackendController(cc) with Logging {

  def deleteCISDeductionsSubmission(nino: String, taxYear: Int, submissionId: String): Action[AnyContent] = auth.async { implicit user =>
    logger.info(s"[DeleteCISDeductionsSubmissionController][deleteCISDeductionsSubmission]" +
      s" Attempting to delete submission: $submissionId, nino: $nino, tax year: $taxYear")
    service.deleteCISDeductionsSubmission(nino, submissionId).map {
      case Right(_) => NoContent
      case Left(errorModel) => Status(errorModel.status)(errorModel.toJson)
    }
  }
}
