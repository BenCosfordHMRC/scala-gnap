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

package data.api

import data.InteractFinish

sealed trait InteractStart
case object REDIRECT extends InteractStart
case object APP extends InteractStart
case object USER_CODE extends InteractStart
case object USER_CODE_URI extends InteractStart

case class InteractRequest(finish: Option[InteractFinish] = None,
                           start: Set[InteractStart] = Set.empty,
                           hints: Option[InteractHintRequest] = None
                          )

object InteractRequest {

}
