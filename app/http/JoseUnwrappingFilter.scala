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

import com.nimbusds.jose.JOSEObject

import java.io.{BufferedReader, ByteArrayInputStream, InputStreamReader}
import java.text.ParseException
import javax.servlet._
import javax.servlet.http.{HttpServletRequest, HttpServletRequestWrapper, HttpUpgradeHandler}

object JoseUnwrappingFilter extends Filter {

  val BODY_JOSE = "BODY_JOSE"

  override def doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain): Unit = {
    val req = request.asInstanceOf[HttpServletRequest]
    if (req.getContentType != null && req.getContentType == "application/jose") {
      val requestWrapper = JoseRequestWrapper(req)

      requestWrapper match {
        case Some(requestWrapper) =>
          processJose(requestWrapper)
          chain.doFilter(requestWrapper, response)
          true
        case None => false
      }

    } else { // it's not a JOSE payload, ignore it
      chain.doFilter(request, response)
      true
    }
  }

  private def processJose(requestWrapper: JoseRequestWrapper): Unit = {
    val jose = requestWrapper.jose
    /*
        log.info(IntStream.range(0, bytes.length)
          .map(idx -> Byte.toUnsignedInt(bytes[idx]))
          .mapToObj(i -> Integer.toHexString(i))
          .collect(Collectors.joining(", ")));
         */
    // save the original JOSE item as an inbound attribute
    requestWrapper.setAttribute(BODY_JOSE, jose)
  }
}

trait CachingRequestWrapper {
  val delegate: HttpServletRequest
  val savedInputStream: ServletInputStream
  val savedReader: BufferedReader
  val savedBody: Array[Byte]
}

case class JoseRequestWrapper(delegate: HttpServletRequest,
                              savedInputStream: ServletInputStream,
                              savedReader: BufferedReader,
                              savedBody: Array[Byte],
                              jose: JOSEObject,
                              length: Long) extends HttpServletRequestWrapper(delegate) with CachingRequestWrapper {

  override def getReader: BufferedReader = savedReader
  override def getInputStream: ServletInputStream = savedInputStream
  override def upgrade[T <: HttpUpgradeHandler](httpUpgradeHandlerClass: Class[T]): T = delegate.upgrade(httpUpgradeHandlerClass)
  override def getContentType: String = "application/json"
  override def getContentLength: Int = length.toInt
  override def getContentLengthLong: Long = length

  override def getHeader(name: String): String = {
    if (name.equalsIgnoreCase("content-type")) {
      getContentType
    } else if(name.equalsIgnoreCase("content-length")){
      getContentLength.toString
    } else {
      delegate.getHeader(name)
    }
  }
//  import java.util
//  import java.util.{Collections, Enumeration, List}
//  override def getHeaders(name: String): util.Enumeration[String] = {
//    if (name.equalsIgnoreCase("content-type")){
//      Collections.enumeration(util.List.of(getContentType))
//    } else if (name.equalsIgnoreCase("content-length")){
//      Collections.enumeration(util.List.of(getContentLength.toString))
//    } else {
//      delegate.getHeaders(name)
//    }
//  }
}

object JoseRequestWrapper {

  def apply(delegate: HttpServletRequest): Option[JoseRequestWrapper] = {

    try {
      val savedBody = delegate.getInputStream.readAllBytes
      val jose = JOSEObject.parse(new String(savedBody))

      // make the payload of the JWT available to the rest of the system
      val payload = jose.getPayload.toBytes

      val sourceStream = new ByteArrayInputStream(payload)

      Some(JoseRequestWrapper(
        delegate = delegate,
        savedInputStream = DelegatingServletInputStream(sourceStream),
        savedReader = new BufferedReader(new InputStreamReader(sourceStream)),
        savedBody = savedBody,
        jose = jose,
        length = savedBody.length
      ))
    } catch {
      case _: ParseException =>
        None
    }
  }
}
