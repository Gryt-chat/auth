/**
 * The background shader.
 *
 * Kept in its own file on purpose: the whole look of the page background is
 * this one string, so changing it later means editing here and nothing else.
 * Nothing outside reads it apart from ShaderBackground.tsx.
 *
 * Colours are @gryt/ui's, converted to 0-1 floats because GLSL has no idea what
 * a hex triplet is:
 *   #111318 background   -> vec3(0.067, 0.075, 0.094)
 *   #968ff8 accent       -> vec3(0.588, 0.561, 0.973)
 *   #7dd3fc secondary    -> vec3(0.490, 0.827, 0.988)
 *
 * If those tokens ever move, these move with them — there is no import that
 * would catch the drift for us.
 */

/** A fullscreen triangle. No transforms; the fragment shader does the work. */
export const VERTEX_SHADER = /* glsl */ `
attribute vec2 position;

void main() {
  gl_Position = vec4(position, 0.0, 1.0);
}
`;

export const FRAGMENT_SHADER = /* glsl */ `
precision highp float;

uniform vec2 resolution;
uniform float time;

// Hash-based value noise. Cheap, and good enough at this scale — nobody is
// inspecting the gradient of a login background.
float hash(vec2 p) {
  return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453);
}

float noise(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  f = f * f * (3.0 - 2.0 * f);
  return mix(
    mix(hash(i), hash(i + vec2(1.0, 0.0)), f.x),
    mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), f.x),
    f.y
  );
}

// Five octaves. Past that the extra detail is smaller than a pixel once the
// result is this soft, so it costs GPU time and shows nothing.
float fbm(vec2 p) {
  float value = 0.0;
  float amplitude = 0.5;
  for (int i = 0; i < 5; i++) {
    value += amplitude * noise(p);
    p *= 2.03;
    amplitude *= 0.5;
  }
  return value;
}

void main() {
  // Divide by height on both axes so the pattern does not stretch when the
  // window is wide.
  vec2 uv = (gl_FragCoord.xy - 0.5 * resolution) / resolution.y;

  // Domain warp: feed noise back into itself so the flow curls instead of
  // sliding, which is what stops it reading as a scrolling texture.
  float f = fbm(uv * 1.7 + vec2(time * 0.035, time * 0.022));
  f = fbm(uv * 1.9 + vec2(f * 1.1, -time * 0.028));

  vec3 colour = vec3(0.067, 0.075, 0.094);
  colour = mix(colour, vec3(0.588, 0.561, 0.973), smoothstep(0.35, 0.95, f) * 0.55);
  colour = mix(colour, vec3(0.490, 0.827, 0.988), smoothstep(0.55, 1.05, f) * 0.18);

  // A little noise, because eight-bit output banding is very visible across a
  // gradient this smooth and this dark.
  colour += (hash(gl_FragCoord.xy) - 0.5) * 0.015;

  gl_FragColor = vec4(colour, 1.0);
}
`;

/** Seconds into the animation to freeze at when motion is not wanted. */
export const REDUCED_MOTION_TIME = 8.0;
