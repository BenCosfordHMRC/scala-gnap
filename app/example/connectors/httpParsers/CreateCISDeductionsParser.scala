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

import example.models.{CreateCISDeductionsSuccess, DesErrorModel}
import example.utils.PagerDutyHelper.PagerDutyKeys._
import example.utils.PagerDutyHelper.pagerDutyLog
import play.api.Logging
import play.api.http.Status._
import uk.gov.hmrc.http.{HttpReads, HttpResponse}

object CreateCISDeductionsParser extends DESParser with Logging{
  type CreateCISDeductionsResponse = Either[DesErrorModel, CreateCISDeductionsSuccess]

  override val parserName = "createCISDeductionsParser"

  implicit object CreateCISDeductionsResponseHttpReads extends HttpReads[CreateCISDeductionsResponse] {
    override def read(method:String, url: String, response:  HttpResponse): CreateCISDeductionsResponse = {
      response.status match {
        case OK => response.json.validate[CreateCISDeductionsSuccess].fold[CreateCISDeductionsResponse](
          _ => badSuccessJsonFromDES,
          responseModel => Right(responseModel)
        )
        case CONFLICT | BAD_REQUEST | UNPROCESSABLE_ENTITY =>
          pagerDutyLog(FOURXX_RESPONSE_FROM_DES, logMessage(response))
          handleDESError(response)
        case INTERNAL_SERVER_ERROR =>
          pagerDutyLog(INTERNAL_SERVER_ERROR_FROM_DES, logMessage(response))
          handleDESError(response)
        case SERVICE_UNAVAILABLE =>
          pagerDutyLog(SERVICE_UNAVAILABLE_FROM_DES, logMessage(response))
          handleDESError(response)
        case _ =>
          pagerDutyLog(UNEXPECTED_RESPONSE_FROM_DES, logMessage(response))
          handleDESError(response, Some(INTERNAL_SERVER_ERROR))
      }
    }
  }
}
