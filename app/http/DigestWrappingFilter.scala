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

package http

import java.io.{BufferedReader, ByteArrayInputStream, InputStream, InputStreamReader}
import javax.servlet.http.{HttpServletRequest, HttpServletRequestWrapper, HttpUpgradeHandler}
import javax.servlet._

object DigestWrappingFilter extends Filter {

  val BODY_BYTES = "BODY_BYTES"

  override def doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain): Unit = {
    val requestWrapper: DigestRequestWrapper = DigestRequestWrapper(request.asInstanceOf[HttpServletRequest])
    attachBodyBytes(requestWrapper)
    chain.doFilter(requestWrapper, response)
  }

  private def attachBodyBytes(requestWrapper: DigestRequestWrapper): Unit = {
    val bytes: Array[Byte] = requestWrapper.savedBody
    /*
        log.info(IntStream.range(0, bytes.length)
          .map(idx -> Byte.toUnsignedInt(bytes[idx]))
          .mapToObj(i -> Integer.toHexString(i))
          .collect(Collectors.joining(", ")));
         */
    requestWrapper.setAttribute(BODY_BYTES, bytes)
  }
}

case class DigestRequestWrapper(delegate: HttpServletRequest,
                                savedInputStream: ServletInputStream,
                                savedReader: BufferedReader,
                                savedBody: Array[Byte]) extends HttpServletRequestWrapper(delegate) with CachingRequestWrapper {

  override def getReader: BufferedReader = savedReader
  override def getInputStream: ServletInputStream = savedInputStream
  override def upgrade[T <: HttpUpgradeHandler](httpUpgradeHandlerClass: Class[T]): T = delegate.upgrade(httpUpgradeHandlerClass)
}

object DigestRequestWrapper {

  def apply(delegate: HttpServletRequest): DigestRequestWrapper = {

    val savedBody = delegate.getInputStream.readAllBytes
    val sourceStream = new ByteArrayInputStream(savedBody)

    DigestRequestWrapper(
      delegate = delegate,
      savedInputStream = DelegatingServletInputStream(sourceStream),
      savedReader = new BufferedReader(new InputStreamReader(sourceStream)),
      savedBody = savedBody
    )
  }
}

private trait ExcludeReaderAndInputStream {
  def getInputStream: ServletInputStream

  def getReader: BufferedReader

  def upgrade[T <: HttpUpgradeHandler](httpUpgradeHandlerClass: Class[T]): T
}

case class DelegatingServletInputStream(sourceStream: InputStream, finished: Boolean = false) extends ServletInputStream {

  override def isFinished: Boolean = finished

  override def isReady: Boolean = true

  override def setReadListener(listener: ReadListener): Unit = throw new UnsupportedOperationException

  override def read(): Int = {
    sourceStream.read
  }

  def readAndUpdate(): DelegatingServletInputStream = {
    val data: Int = read()
    if(data == -1){
      this.copy(finished = true)
    } else {
      this
    }
  }

  override def available: Int = sourceStream.available

  override def close(): Unit = {
    super.close()
    sourceStream.close()
  }
}

object DelegatingServletInputStream {
  def apply(sourceStream: InputStream): Option[DelegatingServletInputStream] = {

    if(sourceStream != null){
      Some(DelegatingServletInputStream(sourceStream))
    } else {
      None
    }
  }
}
