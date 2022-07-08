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
                    interactionUrl: Option[URI] = None,
                    appUrl: Option[URI] = None,
                    interactId: Option[String] = None,
                    serverNonce: Option[String] = None,
                    clientNonce: Option[String] = None,
                    callbackUri: Option[URI] = None,
                    interactRef: Option[String] = None,
                    standaloneUserCode: Option[String] = None,
                    userCode: Option[String] = None,
                    userCodeUrl: Option[URI] = None,
                    callbackMethod: Option[CallbackMethod] = None,
                    callbackHashMethod: Option[HashMethod] = None
                   )

object Interact {
  def apply(interact: InteractRequest): Interact = {

    val interactFinish = interact.finish

    Interact(
      startMethods = interact.start,
      clientNonce = interactFinish.flatMap(_.nonce),
      callbackUri = interactFinish.flatMap(_.uri),
      callbackMethod = interactFinish.map(_.method),
      callbackHashMethod = interactFinish.map(_.hashMethod)
    )
  }
}