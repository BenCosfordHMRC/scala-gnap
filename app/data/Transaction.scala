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

package data

import data.api.{AccessTokenRequest, MultipleAwareField, SubjectRequest}

sealed trait Status
case object NEW extends Status
case object ISSUED extends Status
case object AUTHORIZED extends Status
case object WAITING extends Status
case object DENIED extends Status

case class Transaction(id: String,
                       display: Display,
                       user: User,
                       interact: Interact,
                       interactHandle: String,
                       continueAccessToken: AccessToken,
                       accessToken: MultipleAwareField[AccessToken],
                       status: Status,
                       key: Key,
                       subject: Subject,
                       subjectRequest: SubjectRequest,
                       accessTokenRequest: MultipleAwareField[AccessTokenRequest])

object Transaction {

}