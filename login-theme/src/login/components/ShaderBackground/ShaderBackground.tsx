import { useEffect, useRef } from "react";
import {
  FRAGMENT_SHADER,
  REDUCED_MOTION_TIME,
  VERTEX_SHADER
} from "./shader";

/**
 * The animated page background.
 *
 * Raw WebGL rather than three.js. A fullscreen background is two triangles and
 * a fragment shader; three.js is a scene graph, and it would add roughly 170 KB
 * gzipped to the page standing between someone and the product. The look lives
 * entirely in ./shader.ts, so changing it later is one file.
 *
 * It degrades rather than breaks:
 * - No WebGL, or a shader that fails to compile, leaves the canvas absent and
 *   the CSS gradient underneath shows instead. Nobody sees a black rectangle.
 * - prefers-reduced-motion renders a single frame and stops.
 * - A hidden tab stops drawing, because a login page left open in a background
 *   tab has no business spinning the GPU.
 */
export function ShaderBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null) return;

    const gl = canvas.getContext("webgl", {
      alpha: false,
      antialias: false,
      // The frame is never read back, and letting the driver discard it after
      // compositing is cheaper.
      preserveDrawingBuffer: false,
      powerPreference: "low-power"
    });

    if (gl === null) {
      canvas.remove();
      return;
    }

    const compile = (type: number, source: string) => {
      const shader = gl.createShader(type);
      if (shader === null) return null;
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        // Worth surfacing: a shader that fails to compile is otherwise a
        // completely silent blank background.
        console.warn("gryt: background shader failed to compile", gl.getShaderInfoLog(shader));
        gl.deleteShader(shader);
        return null;
      }
      return shader;
    };

    const vertex = compile(gl.VERTEX_SHADER, VERTEX_SHADER);
    const fragment = compile(gl.FRAGMENT_SHADER, FRAGMENT_SHADER);
    const program = gl.createProgram();

    if (vertex === null || fragment === null || program === null) {
      canvas.remove();
      return;
    }

    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);

    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      console.warn("gryt: background shader failed to link", gl.getProgramInfoLog(program));
      canvas.remove();
      return;
    }

    gl.useProgram(program);

    // One triangle large enough to cover the viewport. Cheaper than two, and
    // avoids the seam a quad can show along its diagonal.
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 3, -1, -1, 3]),
      gl.STATIC_DRAW
    );

    const positionLocation = gl.getAttribLocation(program, "position");
    gl.enableVertexAttribArray(positionLocation);
    gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0);

    const resolutionLocation = gl.getUniformLocation(program, "resolution");
    const timeLocation = gl.getUniformLocation(program, "time");

    const prefersReducedMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    );

    const resize = () => {
      // Capped at 2: beyond that the buffer grows quadratically for detail
      // nobody can see in a blurred gradient, and it is the difference between
      // smooth and stuttering on a 3x phone.
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const width = Math.max(1, Math.round(canvas.clientWidth * dpr));
      const height = Math.max(1, Math.round(canvas.clientHeight * dpr));
      if (canvas.width === width && canvas.height === height) return;
      canvas.width = width;
      canvas.height = height;
    };

    let frame = 0;
    let start = 0;

    const draw = (seconds: number) => {
      resize();
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform2f(resolutionLocation, canvas.width, canvas.height);
      gl.uniform1f(timeLocation, seconds);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    };

    const loop = (timestamp: number) => {
      frame = requestAnimationFrame(loop);
      if (start === 0) start = timestamp;
      draw((timestamp - start) / 1000);
    };

    const stop = () => {
      if (frame !== 0) {
        cancelAnimationFrame(frame);
        frame = 0;
      }
    };

    const startOrDrawOnce = () => {
      stop();
      if (prefersReducedMotion.matches) {
        // A composed still, not a blank canvas — the design without the motion.
        draw(REDUCED_MOTION_TIME);
        return;
      }
      start = 0;
      frame = requestAnimationFrame(loop);
    };

    const onVisibility = () => {
      if (document.hidden) stop();
      else startOrDrawOnce();
    };

    startOrDrawOnce();

    const observer = new ResizeObserver(() => {
      if (frame === 0) draw(REDUCED_MOTION_TIME);
    });
    observer.observe(canvas);

    prefersReducedMotion.addEventListener("change", startOrDrawOnce);
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      stop();
      observer.disconnect();
      prefersReducedMotion.removeEventListener("change", startOrDrawOnce);
      document.removeEventListener("visibilitychange", onVisibility);
      gl.deleteProgram(program);
      gl.deleteShader(vertex);
      gl.deleteShader(fragment);
      gl.deleteBuffer(buffer);
      // Frees the GPU context immediately rather than waiting for collection,
      // which matters because StrictMode mounts this twice in development.
      gl.getExtension("WEBGL_lose_context")?.loseContext();
    };
  }, []);

  return (
    <div className="gryt-auth-backdrop" aria-hidden="true">
      <canvas ref={canvasRef} className="gryt-auth-shader" />
    </div>
  );
}
