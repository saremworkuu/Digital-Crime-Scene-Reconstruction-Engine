import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

export const CyberMeshBackground3D: React.FC<{ className?: string }> = ({ className = '' }) => {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const width = mount.clientWidth || window.innerWidth;
    const height = mount.clientHeight || window.innerHeight;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(55, width / height, 0.1, 1000);
    camera.position.set(0, 30, 80);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mount.replaceChildren(renderer.domElement);

    // Grid of particles forming a cyber mesh wave
    const cols = 55;
    const rows = 45;
    const count = cols * rows;
    const spacing = 4.2;

    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);

    let idx = 0;
    for (let c = 0; c < cols; c++) {
      for (let r = 0; r < rows; r++) {
        const x = (c - cols / 2) * spacing;
        const z = (r - rows / 2) * spacing;
        const y = 0;

        positions[idx * 3] = x;
        positions[idx * 3 + 1] = y;
        positions[idx * 3 + 2] = z;

        // Gradient from orange near center to dark warm ember at edges
        const distFromCenter = Math.sqrt(x * x + z * z);
        const normDist = Math.min(1, distFromCenter / 120);

        colors[idx * 3] = 1.0 - normDist * 0.4; // R (vibrant orange to red)
        colors[idx * 3 + 1] = 0.28 * (1.0 - normDist); // G
        colors[idx * 3 + 2] = 0.12 * (1.0 - normDist); // B

        idx++;
      }
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    // Particle sprite
    const canvas = document.createElement('canvas');
    canvas.width = 32;
    canvas.height = 32;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      const grad = ctx.createRadialGradient(16, 16, 0, 16, 16, 16);
      grad.addColorStop(0, 'rgba(255, 255, 255, 1)');
      grad.addColorStop(0.3, 'rgba(255, 75, 30, 0.8)');
      grad.addColorStop(0.8, 'rgba(255, 75, 30, 0.2)');
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 32, 32);
    }
    const texture = new THREE.CanvasTexture(canvas);

    const material = new THREE.PointsMaterial({
      size: 2.8,
      vertexColors: true,
      map: texture,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const pointCloud = new THREE.Points(geometry, material);
    scene.add(pointCloud);

    // Connecting grid lines with low opacity
    const lineIndices: number[] = [];
    for (let c = 0; c < cols; c++) {
      for (let r = 0; r < rows; r++) {
        const i = c * rows + r;
        if (c < cols - 1) {
          lineIndices.push(i, (c + 1) * rows + r);
        }
        if (r < rows - 1) {
          lineIndices.push(i, c * rows + (r + 1));
        }
      }
    }
    const lineGeo = new THREE.BufferGeometry();
    lineGeo.setAttribute('position', geometry.attributes.position);
    lineGeo.setIndex(lineIndices);

    const lineMat = new THREE.LineBasicMaterial({
      color: 0xff461e,
      transparent: true,
      opacity: 0.12
    });
    const gridLines = new THREE.LineSegments(lineGeo, lineMat);
    scene.add(gridLines);

    let mouseX = 0;
    let mouseY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      mouseX = (e.clientX / window.innerWidth - 0.5) * 20;
      mouseY = (e.clientY / window.innerHeight - 0.5) * 20;
    };

    window.addEventListener('mousemove', handleMouseMove);

    let animationId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationId = requestAnimationFrame(animate);
      const time = clock.getElapsedTime() * 0.8;

      const posArr = geometry.attributes.position.array as Float32Array;
      let pIdx = 0;

      for (let c = 0; c < cols; c++) {
        for (let r = 0; r < rows; r++) {
          const x = posArr[pIdx * 3];
          const z = posArr[pIdx * 3 + 2];
          // Harmonic wave equation
          const wave = Math.sin(x * 0.08 + time) * 3.5 + Math.cos(z * 0.08 + time * 0.9) * 3.5;
          posArr[pIdx * 3 + 1] = wave;
          pIdx++;
        }
      }

      geometry.attributes.position.needsUpdate = true;
      lineGeo.attributes.position.needsUpdate = true;

      // Parallax camera tilt with mouse
      camera.position.x += (mouseX - camera.position.x) * 0.03;
      camera.position.y += (30 - mouseY - camera.position.y) * 0.03;
      camera.lookAt(0, 0, 0);

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!mount) return;
      const w = mount.clientWidth || window.innerWidth;
      const h = mount.clientHeight || window.innerHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
      geometry.dispose();
      material.dispose();
      lineGeo.dispose();
      lineMat.dispose();
      texture.dispose();
    };
  }, []);

  return <div ref={mountRef} className={`absolute inset-0 pointer-events-none ${className}`} />;
};
