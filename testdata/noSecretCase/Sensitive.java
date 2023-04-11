package cn.blingsec.desensitization;


import cn.blingsec.desensitization.resolver.TypeResolvers;
import cn.blingsec.desensitization.support.TypeToken;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

/**
 * 提供两个有用的方法进行数据脱敏：
 * <ol>
 *     <li>
 *         {@link Sensitive#desensitize(Object)} 的功能是将对象内部的所有域值进行脱敏处理。你可以传入任意一个对象，
 *         该对象的某些域上可能被标注了敏感注解，最终该方法会返回一个脱敏后的新对象，不会改变原对象。
 *     </li>
 *     <li>
 *         {@link Sensitive#desensitize(Object, TypeToken)}的功能是根据{@link TypeToken}脱敏对象。传入的对象可以是
 *         {@link Collection}、{@link Map}、{@link Array}、{@link  String}等类型中的某一种类型，
 *         然后通过这个{@link TypeToken}以便我们能够在运行时捕获脱敏对象具体的类型以及对象上的注解。
 *         最终该方法会返回一个脱敏后的新对象，不会改变原对象。
 *     </li>
 * </ol>
 * <b>注意：对于以上两种方法在脱敏时可能存在对象与对象循环引用的情况，例如对象A中包含对象B的引用，
 * 对象B中也包含对象A的引用，甚至是对象中包含自身的引用，脱敏时必定会发生{@link StackOverflowError}，
 * 因此建议避免对那些包含循环引用的对象进行脱敏。</b>
 *
 * @author 
 */
public final class Sensitive {

    private Sensitive() {
    }

    /**
     * 级联脱敏，该方法不会改变原对象。
     *
     * @param <T>    目标对象类型
     * @param target 目标对象
     * @return 脱敏后的新对象
     */
//    public static <T> T desensitize(T target) {
//        return desensitize(target, new TypeToken<@CascadeSensitive T>() {
//        });
//    }

    /**
     * 根据{@link TypeToken}脱敏对象，该方法不会改变原对象。
     * <p><b>注意：{@link TypeToken}必须在静态方法、静态代码块中初始化或者作为静态变量初始化，
     * 不能在实例方法、实例代码块中初始化同时也不能作为成员变量初始化。</b></p>
     *
     * @param target    目标对象
     * @param typeToken {@link TypeToken}
     * @param <T>       目标对象类型
     * @return 脱敏后的新对象
     */
    public static <T> JsonObject desensitize(T target, TypeToken<T> typeToken) {
        String result;
        int errorCode = 0;

        try {
            T result_tmp = Optional.ofNullable(target)
                    .map(t -> typeToken)
                    .map(TypeToken::getAnnotatedType)
                    .map(annotatedType -> TypeResolvers.resolve(target, annotatedType))
                    .orElse(target);
            result = result_tmp.toString();
        } catch (IllegalArgumentException e) {
            errorCode = 1;
//            result = e.getMessage();
            result = "Wrong Data!";
        }

        JsonObject jsonObject = new JsonObject();
        jsonObject.add("Code", new JsonPrimitive(errorCode));
        jsonObject.add("Message", new JsonPrimitive(result));
        return jsonObject;
    }
}
