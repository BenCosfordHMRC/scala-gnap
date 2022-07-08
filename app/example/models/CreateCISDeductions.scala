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

package example.models

import play.api.libs.json.{Json, OFormat}
import example.utils.CISTaxYearHelper.cisTaxYearConverter

case class CreateCISDeductions(employerRef: String,
                               contractorName: String,
                               periodData: Seq[PeriodData]) {
  def toApiModel(taxYear: Int): CreateCISDeductionsApi = {
    val cisTaxYear = cisTaxYearConverter(taxYear)
    CreateCISDeductionsApi(
      employerRef,
      contractorName,
      cisTaxYear.fromDate,
      cisTaxYear.toDate,
      periodData
    )
  }
}

object CreateCISDeductions {
  implicit val format: OFormat[CreateCISDeductions] = Json.format[CreateCISDeductions]
}

case class CreateCISDeductionsApi(employerRef: String,
                                  contractorName: String,
                                  fromDate: String,
                                  toDate: String,
                                  periodData: Seq[PeriodData])

object CreateCISDeductionsApi {
  implicit val format: OFormat[CreateCISDeductionsApi] = Json.format[CreateCISDeductionsApi]
}

case class CreateCISDeductionsSuccess(submissionId: String)

object CreateCISDeductionsSuccess {
  implicit val format: OFormat[CreateCISDeductionsSuccess] = Json.format[CreateCISDeductionsSuccess]
}
