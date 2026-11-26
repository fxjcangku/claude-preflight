/* Orthographic reference globe. Land samples are derived from Natural Earth. */
(() => {
  "use strict";
  const canvas = document.getElementById("route-globe");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  let atlas = {land: [], centers: {}};
  let country = null;
  const rad = Math.PI / 180;

  function paint() {
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    if (!width || !height) return;
    const dpi = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * dpi);
    canvas.height = Math.round(height * dpi);
    ctx.setTransform(dpi, 0, 0, dpi, 0, 0);
    const cx = width * 0.5;
    const cy = height * 0.50;
    const r = Math.min(width * 0.44, height * 0.44);
    const marker = country && atlas.centers[country];
    const view = marker || [95, 16];
    const lon0 = (view[0] - 18) * rad;
    const lat0 = Math.max(-60, Math.min(70, view[1] + 10)) * rad;
    const sin0 = Math.sin(lat0), cos0 = Math.cos(lat0);
    function project(lon, lat) {
      const d = lon * rad - lon0;
      const s = Math.sin(lat * rad), c = Math.cos(lat * rad);
      return [cx + r*c*Math.sin(d), cy - r*(cos0*s - sin0*c*Math.cos(d)),
              sin0*s + cos0*c*Math.cos(d)];
    }
    function circle(x, y, radius) {
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI*2);
    }
    const sea = ctx.createRadialGradient(cx-r*.4, cy-r*.5, 0, cx, cy, r);
    sea.addColorStop(0, "#193c3c");
    sea.addColorStop(.82, "#0b272c");
    sea.addColorStop(1, "#163e3d");
    circle(cx, cy, r);
    ctx.fillStyle = sea;
    ctx.fill();
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = "rgba(108,239,194,.50)";
    ctx.stroke();
    function gridLine(sample, start, end) {
      ctx.beginPath();
      let visible = false;
      for (let angle=start; angle<=end; angle+=3) {
        const [x,y,z] = project(...sample(angle));
        if (z >= 0) {
          if (visible) ctx.lineTo(x,y); else ctx.moveTo(x,y);
        }
        visible = z >= 0;
      }
      ctx.stroke();
    }
    ctx.strokeStyle = "rgba(103,220,195,.17)";
    for (let lat=-60; lat<=60; lat+=30) gridLine(lon=>[lon,lat],-180,180);
    for (let lon=-180; lon<180; lon+=30) gridLine(lat=>[lon,lat],-90,90);
    for (const [lon,lat] of atlas.land) {
      const [x,y,z] = project(lon,lat);
      if (z <= 0) continue;
      circle(x,y,Math.max(.55,r*.009)*(0.55+z*.45));
      ctx.fillStyle = "rgba(130,242,200," + (.29+z*.57) + ")";
      ctx.fill();
    }
    if (marker) {
      const [x,y] = project(...marker);
      const glow = ctx.createRadialGradient(x,y,0,x,y,17);
      glow.addColorStop(0,"rgba(164,255,207,.68)");
      glow.addColorStop(1,"rgba(109,255,191,0)");
      circle(x,y,17); ctx.fillStyle=glow; ctx.fill();
      circle(x,y,6.2); ctx.strokeStyle="#b0f9c6"; ctx.stroke();
      circle(x,y,2.8); ctx.fillStyle="#dcffe5"; ctx.fill();
    }
    const name = marker ? country + " 地区参考位置" : "世界示意图";
    canvas.setAttribute("aria-label", name);
  }
  window.drawPreflightGlobe = value => { country = value || null; paint(); };
  new ResizeObserver(paint).observe(canvas);
  fetch("world.json").then(r => r.ok ? r.json() : Promise.reject())
    .then(data => {atlas = data; paint();}).catch(paint);
})();
