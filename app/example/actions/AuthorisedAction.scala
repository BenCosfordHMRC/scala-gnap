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

package example.actions

import example.models.User
import play.api.Logger
import play.api.mvc.Results.Unauthorized
import play.api.mvc._
import uk.gov.hmrc.auth.core._
import uk.gov.hmrc.auth.core.retrieve.v2.Retrievals.affinityGroup
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.play.http.HeaderCarrierConverter

import javax.inject.Inject
import scala.concurrent.{ExecutionContext, Future}

class AuthorisedAction @Inject()()(implicit val authConnector: AuthConnector,
                                   defaultActionBuilder: DefaultActionBuilder,
                                   val cc: ControllerComponents) extends AuthorisedFunctions {

  lazy val logger: Logger = Logger.apply(this.getClass)
  implicit val executionContext: ExecutionContext = cc.executionContext

  val unauthorized: Future[Result] = Future(Unauthorized)

  def async(block: User[AnyContent] => Future[Result]): Action[AnyContent] = defaultActionBuilder.async { implicit request =>

    implicit lazy val headerCarrier: HeaderCarrier = HeaderCarrierConverter.fromRequest(request)

    authorised.retrieve(affinityGroup) {
      case Some(a:AffinityGroup) => block(User(a))
    } recover {
      case _: NoActiveSession =>
        logger.info(s"[AuthorisedAction][async] - No active session.")
        Unauthorized
      case _: AuthorisationException =>
        logger.info(s"[AuthorisedAction][async] - User failed to authenticate")
        Unauthorized
    }
  }
}
