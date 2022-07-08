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
import example.models.get.AllCISDeductions
import example.services.CISDeductionsService

import javax.inject.Inject
import play.api.libs.json.Json
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController

import scala.concurrent.ExecutionContext

class GetCISDeductionsController @Inject()(service: CISDeductionsService,
                                           auth: AuthorisedAction,
                                           cc: ControllerComponents)
                                          (implicit ec: ExecutionContext) extends BackendController(cc) {

  def getCISDeductions(nino: String, taxYear: Int): Action[AnyContent] = auth.async { implicit user =>
    service.getCISDeductions(nino, taxYear).map {
      case Right(AllCISDeductions(None, None)) => NoContent
      case Right(model) => Ok(Json.toJson(model))
      case Left(errorModel) => Status(errorModel.status)(errorModel.toJson)
    }
  }
}
