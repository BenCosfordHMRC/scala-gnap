/*
 * Copyright 2020 HM Revenue & Customs
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

package data

import crypto.HashMethod
import data.api.InteractRequest

import java.net.URI

sealed trait InteractStart
case object REDIRECT extends InteractStart
case object APP extends InteractStart
case object USER_CODE extends InteractStart
case object USER_CODE_URI extends InteractStart

case class Interact(startMethods: Set[InteractStart] = Set.empty,
                    interactionUrl: URI,
                    appUrl: URI,
                    interactId: String,
                    serverNonce: String,
                    clientNonce: String,
                    callbackUri: URI,
                    interactRef: String,
                    standaloneUserCode: String,
                    userCode: String,
                    userCodeUrl: URI,
                    callbackMethod: CallbackMethod,
                    callbackHashMethod: HashMethod
                   )

object Interact {
  def apply(interact: InteractRequest): Interact ={

    val interactFinish = interact.finish

    Interact(
      startMethods = interact.start,
      interactionUrl = ???,
      appUrl = ???,
      interactId = ???,
      serverNonce = ???,
      clientNonce = interactFinish.map(_.nonce),
      callbackUri = interactFinish.map(_.uri),
      interactRef = ???,
      standaloneUserCode = ???,
      userCode = ???,
      userCodeUrl = ???,
      callbackMethod = interactFinish.map(_.method),
      callbackHashMethod = interac
    )


//      .setStartMethods(Optional.ofNullable(interact.getStart()).orElse(Collections.emptySet()))
//      .setCallbackMethod(interactFinish.map(InteractFinish::getMethod).orElse(null))
//      .setCallbackUri(interactFinish.map(InteractFinish::getUri).orElse(null))
//      .setClientNonce(interactFinish.map(InteractFinish::getNonce).orElse(null))
//      .setCallbackHashMethod(interactFinish.map(InteractFinish::getHashMethod).orElse(null));
  }
}