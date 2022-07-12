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
import example.utils.TestUtils
import play.api.http.Status._
import play.api.mvc.Results._
import play.api.mvc.{AnyContent, Result}
import uk.gov.hmrc.auth.core._

import scala.concurrent.Future

class AuthorisedActionSpec extends TestUtils {

  val auth: AuthorisedAction = authorisedAction

  ".async" should {

    lazy val block: User[AnyContent] => Future[Result] = user =>
      Future.successful(Ok(s"Agent ${user.isAgent}"))

    "perform the block action" when {

      "the user is successfully verified as an agent" which {

        lazy val result: Future[Result] = {
          mockAuthAsAgent()
          auth.async(block)(fakeRequest)
        }

        "should return an OK(200) status" in {

          status(result) mustBe OK
          bodyOf(result) mustBe "Agent true"
        }
      }

      "the user is successfully verified as an individual" in {

        lazy val result = {
          mockAuth()
          auth.async(block)(fakeRequest)
        }

        status(result) mustBe OK
        bodyOf(result) mustBe "Agent false"
      }
    }

    "return an Unauthorised" when {

      "the authorisation service returns an AuthorisationException exception" in {
        object AuthException extends AuthorisationException("Some reason")

        lazy val result = {
          mockAuthReturnException(AuthException)
          auth.async(block)
        }

        status(result(fakeRequest)) mustBe UNAUTHORIZED
      }

    }

    "return an Unauthorised" when {

      "the authorisation service returns a NoActiveSession exception" in {
        object NoActiveSession extends NoActiveSession("Some reason")

        lazy val result = {
          mockAuthReturnException(NoActiveSession)
          auth.async(block)
        }

        status(result(fakeRequest)) mustBe UNAUTHORIZED
      }
    }

  }
}
