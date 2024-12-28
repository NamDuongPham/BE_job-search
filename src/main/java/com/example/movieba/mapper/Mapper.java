package com.example.movieba.mapper;

import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public interface Mapper {
    default <T, P> List<P> toList(List<T> list, Function<T, P> map) {
        return list.stream().map(map::apply).collect(Collectors.toList());
    }

    default <T, P> Set<P> toSet(List<T> list, Function<T, P> map) {
        return list.stream().map(map::apply).collect(Collectors.toSet());
    }
}
