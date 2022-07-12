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

import example.utils.TestUtils
import play.api.http.Status.OK

class HelloWorldControllerSpec extends TestUtils {

  val controller = new HelloWorldController(authorisedAction, mockControllerComponents)

  "calling .helloWorld" should {
    "when user is individual" should {
      "return an OK 200 response with hello individual" in {
        val result = {
          mockAuth()
          controller.helloWorld()(fakeRequest)
        }
        status(result) mustBe OK
        bodyOf(result) mustBe "Hello Individual"
      }
    }
  }
}
