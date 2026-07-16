package com.example;

import java.util.List;

public class SampleController {
    static {
        System.setProperty("fixture", "true");
    }

    {
        value = "initialized";
    }

    private String value;

    public SampleController() {
    }

    public String show(String input) {
        Runnable callback = () -> System.out.println(input);
        callback.run();
        return input;
    }

    public List<String> map(List<String> values) {
        return values.stream().map(value -> value.trim()).toList();
    }

    static class Nested {
        void execute() {
        }
    }
}
