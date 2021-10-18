/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access.intercept;

import java.util.Collection;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * Creates a new temporary {@link Authentication} object for the current secure object
 * invocation only.
 *
 * <p>
 * This interface permits implementations to replace the <code>Authentication</code>
 * object that applies to the current secure object invocation only. The
 * {@link org.springframework.security.access.intercept.AbstractSecurityInterceptor} will
 * replace the <code>Authentication</code> object held in the
 * {@link org.springframework.security.core.context.SecurityContext SecurityContext} for
 * the duration of the secure object callback only, returning it to the original
 * <code>Authentication</code> object when the callback ends.
 * </p>
 *
 * <p>
 * This is provided so that systems with two layers of objects can be established. One
 * layer is public facing and has normal secure methods with the granted authorities
 * expected to be held by external callers. The other layer is private, and is only
 * expected to be called by objects within the public facing layer. The objects in this
 * private layer still need security (otherwise they would be public methods) and they
 * also need security in such a manner that prevents them being called directly by
 * external callers. The objects in the private layer would be configured to require
 * granted authorities never granted to external callers. The <code>RunAsManager</code>
 * interface provides a mechanism to elevate security in this manner.
 * </p>
 *
 * <p>
 * It is expected implementations will provide a corresponding concrete
 * <code>Authentication</code> and <code>AuthenticationProvider</code> so that the
 * replacement <code>Authentication</code> object can be authenticated. Some form of
 * security will need to be implemented to ensure the <code>AuthenticationProvider</code>
 * only accepts <code>Authentication</code> objects created by an authorized concrete
 * implementation of <code>RunAsManager</code>.
 * </p>
 *  仅为当前安全对象调用创建一个新的临时身份验证对象。 此接口允许实现替换仅应用于当前安全对象调用的Authentication对象。AbstractSecurityInterceptor将替换仅在安全对象回调期间保存在SecurityContext中的身份验证对象，并在回调结束时将其返回到原始身份验证对象。 这样就可以建立具有两层对象的系统。一层是面向公共的，具有正常的安全方法，授予的权限预计将由外部调用者持有。另一层是私有的，只能由公共面向层中的对象调用。这个私有层中的对象仍然需要安全性(否则它们将是公共方法)，而且它们还需要防止它们被外部调用者直接调用的安全性。私有层中的对象将被配置为需要未授予外部调用者的授权。RunAsManager接口提供了一种以这种方式提高安全性的机制。 预期实现将提供相应的具体身份验证和AuthenticationProvider，以便替换的身份验证对象能够被身份验证。需要实现某种形式的安全性，以确保AuthenticationProvider只接受由RunAsManager的授权具体实现创建的身份验证对象。
 * @author Ben Alex
 */
public interface RunAsManager {

	/**
	 * Returns a replacement <code>Authentication</code> object for the current secure
	 * object invocation, or <code>null</code> if replacement not required.
	 * @param authentication the caller invoking the secure object
	 * @param object the secured object being called
	 * @param attributes the configuration attributes associated with the secure object
	 * being invoked
	 * @return a replacement object to be used for duration of the secure object
	 * invocation, or <code>null</code> if the <code>Authentication</code> should be left
	 * as is
	 */
	Authentication buildRunAs(Authentication authentication, Object object, Collection<ConfigAttribute> attributes);

	/**
	 * Indicates whether this <code>RunAsManager</code> is able to process the passed
	 * <code>ConfigAttribute</code>.
	 * <p>
	 * This allows the <code>AbstractSecurityInterceptor</code> to check every
	 * configuration attribute can be consumed by the configured
	 * <code>AccessDecisionManager</code> and/or <code>RunAsManager</code> and/or
	 * <code>AfterInvocationManager</code>.
	 * </p>
	 * @param attribute a configuration attribute that has been configured against the
	 * <code>AbstractSecurityInterceptor</code>
	 * @return <code>true</code> if this <code>RunAsManager</code> can support the passed
	 * configuration attribute
	 */
	boolean supports(ConfigAttribute attribute);

	/**
	 * Indicates whether the <code>RunAsManager</code> implementation is able to provide
	 * run-as replacement for the indicated secure object type.
	 * @param clazz the class that is being queried
	 * @return true if the implementation can process the indicated class
	 */
	boolean supports(Class<?> clazz);

}
