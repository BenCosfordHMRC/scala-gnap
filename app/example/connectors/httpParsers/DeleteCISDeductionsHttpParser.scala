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

package example.connectors.httpParsers

import example.models.DesErrorModel
import example.utils.PagerDutyHelper.PagerDutyKeys._
import example.utils.PagerDutyHelper.pagerDutyLog
import play.api.http.Status.{BAD_REQUEST, INTERNAL_SERVER_ERROR, NOT_FOUND, NO_CONTENT, SERVICE_UNAVAILABLE}
import uk.gov.hmrc.http.{HttpReads, HttpResponse}

object DeleteCISDeductionsHttpParser extends DESParser {
  type DeleteCISDeductionsResponse = Either[DesErrorModel, Unit]

  override val parserName: String = "DeleteCISDeductionsHttpParser"

  implicit object DeleteCISDeductionsHttpReads extends HttpReads[DeleteCISDeductionsResponse] {
    override def read(method: String, url: String, response: HttpResponse): DeleteCISDeductionsResponse = {
      response.status match {
        case NO_CONTENT => Right(())
        case BAD_REQUEST | NOT_FOUND =>
          pagerDutyLog(FOURXX_RESPONSE_FROM_DES, logMessage(response))
          handleDESError(response)
        case SERVICE_UNAVAILABLE =>
          pagerDutyLog(SERVICE_UNAVAILABLE_FROM_DES, logMessage(response))
          handleDESError(response)
        case INTERNAL_SERVER_ERROR =>
          pagerDutyLog(INTERNAL_SERVER_ERROR_FROM_DES, logMessage(response))
          handleDESError(response)
        case _ =>
          pagerDutyLog(UNEXPECTED_RESPONSE_FROM_DES, logMessage(response))
          handleDESError(response, Some(INTERNAL_SERVER_ERROR))
      }
    }
  }
}