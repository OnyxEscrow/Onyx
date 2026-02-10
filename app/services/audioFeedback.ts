/**
 * Audio Feedback — Web Audio API synthesized tones
 * Zero dependencies, ~800 bytes. Graceful fallback if AudioContext blocked.
 */

let audioCtx: AudioContext | null = null;

function getCtx(): AudioContext {
  if (!audioCtx) audioCtx = new AudioContext();
  return audioCtx;
}

type Tone = 'success' | 'alert' | 'complete' | 'click';

const TONES: Record<Tone, { freq: number[]; dur: number[]; type: OscillatorType }> = {
  // C-E-G ascending triad (key milestone achieved)
  success:  { freq: [523, 659, 784],  dur: [0.1, 0.1, 0.15],  type: 'sine' },
  // A-C# two-note alert (payment detected, attention needed)
  alert:    { freq: [440, 554],        dur: [0.08, 0.12],       type: 'triangle' },
  // C5-G5-C6 full octave resolution (TX broadcast, escrow settled)
  complete: { freq: [523, 784, 1047],  dur: [0.1, 0.1, 0.3],   type: 'sine' },
  // 800Hz 30ms blip (UI interaction feedback)
  click:    { freq: [800],             dur: [0.03],             type: 'square' },
};

export function playTone(tone: Tone): void {
  try {
    const ctx = getCtx();
    if (ctx.state === 'suspended') {
      ctx.resume();
    }
    const { freq, dur, type } = TONES[tone];
    let time = ctx.currentTime;

    for (let i = 0; i < freq.length; i++) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = type;
      osc.frequency.value = freq[i];
      gain.gain.setValueAtTime(0.12, time);
      gain.gain.exponentialRampToValueAtTime(0.001, time + dur[i]);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(time);
      osc.stop(time + dur[i] + 0.05);
      time += dur[i] * 0.8; // slight overlap for smoother transition
    }
  } catch {
    // Silent fail — AudioContext may be blocked by browser autoplay policy
  }
}
