---
title: Weather Report
theme: dashboard
toc: false
---


# Weather report


```js
const forecast = FileAttachment("./data/forecast.json").json();
```



```js
function temperaturePlot(data, {width} = {} ) {
    return Plot.plot({
    title: "Hourly temperature forecast",
    x: {type: "utc", ticks: "day", label: "Date"},
    y: {grid: true, inset: 10, label: "Degrees (F)"},
    marks: [
      Plot.lineY(forecast.properties.periods, {
        x: "startTime",
        y: "temperature",
        z: null, // varying color, not series
        stroke: "temperature",
        curve: "step-after"
      })
    ]
  });
}
```

```js
display(forecast);
```

<div class="grid grid-cols-1">
  <div class="card grid-colspan-1">${resize((width) => 
  temperaturePlot(forecast, {width}))}
  </div>
</div>

