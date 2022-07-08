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

import data.api.DisplayRequest

case class Display(name: String, uri: String, logoUri: String)

object Display {
  def apply(displayRequest: DisplayRequest): Display ={
    Display(
      name = displayRequest.name,
      uri = displayRequest.uri,
      logoUri = displayRequest.logoUri
    )
  }
}
