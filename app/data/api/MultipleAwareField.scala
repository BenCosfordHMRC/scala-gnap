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

case class MultipleAwareField[Data](multiple: Boolean, data: Seq[Data]){

  def asSingle: Option[Data] = if(multiple) None else data.headOption

  def asMultiple: Seq[Data] = if(multiple) data else Seq.empty
}

object MultipleAwareField {

  def apply[SingleData](singleton: SingleData): MultipleAwareField[SingleData] = {
    MultipleAwareField[SingleData](multiple = false, data = Seq(singleton))
  }

  def apply[MultipleData](items: Seq[MultipleData]): MultipleAwareField[MultipleData] = {
    MultipleAwareField[MultipleData](multiple = true, data = items)
  }

  def apply[OutputData,InputData](input: MultipleAwareField[InputData], function: InputData => OutputData): Option[MultipleAwareField[OutputData]] = {

    if(input.data.nonEmpty){
      Some(MultipleAwareField[OutputData](
        multiple = input.multiple,
        data = input.data.toStream.map(function)
      ))
    } else {
      None
    }
  }
}