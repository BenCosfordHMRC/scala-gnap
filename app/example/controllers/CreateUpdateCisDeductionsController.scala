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
import example.models.{CreateCISDeductionsSuccess, DesErrorModel}
import example.models.submission.CISSubmission
import example.services.CISDeductionsService

import javax.inject.Inject
import play.api.Logging
import play.api.libs.json.{JsSuccess, Json}
import play.api.mvc.{Action, AnyContent, ControllerComponents, Result}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController

import scala.concurrent.{ExecutionContext, Future}

class CreateUpdateCisDeductionsController @Inject()(service: CISDeductionsService,
                                                    auth: AuthorisedAction,
                                                    cc: ControllerComponents)
                                                   (implicit ec: ExecutionContext) extends BackendController(cc) with Logging {

  def postCISDeductions(nino: String, taxYear: Int): Action[AnyContent] = auth.async { implicit user =>
    user.request.body.asJson.map(_.validate[CISSubmission]) match {
      case Some(JsSuccess(model@CISSubmission(Some(_), Some(_), periodData, None), _)) if periodData.nonEmpty  =>
        responseHandler(service.submitCISDeductions(nino, taxYear, model))
      case Some(JsSuccess(model@CISSubmission(None, None, periodData, Some(_)), _)) if periodData.nonEmpty  =>
        responseHandler(service.submitCISDeductions(nino, taxYear, model))
      case _ =>
        logger.warn("[CreateUpdateCisDeductionsController][postCISDeductions] Create update CIS request is invalid")
        Future.successful(BadRequest)
    }
  }

  private def responseHandler(serviceResponse: Future[Either[DesErrorModel, Option[String]]]): Future[Result] ={
    serviceResponse.map {
      case Right(Some(submissionId)) => Ok(Json.toJson(CreateCISDeductionsSuccess(submissionId)))
      case Right(_) => Ok
      case Left(errorModel) => Status(errorModel.status)(Json.toJson(errorModel.toJson))
    }
  }
}
