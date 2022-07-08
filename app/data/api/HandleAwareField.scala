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

case class HandleAwareField[T](handled: Boolean, handle: Option[String] = None, data: Option[T] = None) {

  def asHandle: Option[String] = if(handled) handle else None

  def asValue: Option[T] = if(handled) None else data

}

object HandleAwareField {

  def apply[S](handle: String): HandleAwareField[S] = HandleAwareField[S](handle = Some(handle), handled = true)

  def apply[S](data: S): HandleAwareField[S] = {

    // avoid double-wrapping that Jackson can sometimes try to do
    if (data.isInstanceOf[HandleAwareField[_]]) {
      data.asInstanceOf[HandleAwareField[S]]
    } else {
      HandleAwareField[S](handled = false, data = Some(data))
    }
  }
}